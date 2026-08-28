"""Receipt-bound dynamic Phase-2A successor scope.

The 2026-08-27 held scope remains immutable in :mod:`phase2a_frozen_scope`.
This module is the additive route for the final remediation run: it freezes
the *actual* post-scan catalogue identities instead of relying on the old
251-source/222,200-chunk constants.

No function in this module admits a source, runs a scan, builds an index or
writes an ACTIVE/PREVIOUS pointer.  Scope creation is possible only after a
separately owner-authorized application ledger has named every included and
excluded source binding.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..config import Settings
from ..db import Database
from .phase2a_frozen_scope import (
    CORPUS_ID as PRIOR_PHASE2A_CORPUS_ID,
)
from .phase2a_frozen_scope import (
    load_phase2a_frozen_scope,
    select_phase2a_frozen_scope_rows,
)

DYNAMIC_CORPUS_PREFIX = "current-law-ew-full-phase2a-final-"
DYNAMIC_CORPUS_RE = re.compile(rf"^{re.escape(DYNAMIC_CORPUS_PREFIX)}(?P<identity>[0-9a-f]{{16}})$")
SCOPE_FILENAME = "FROZEN-FINAL-SUCCESSOR-SOURCE-SCOPE.json"
PACKAGE_FILENAME = "PACKAGE-MANIFEST.json"
APPLICATION_LEDGER_SCHEMA = "legalbot.v111.phase2a.owner-application-ledger.v1"
SCOPE_SCHEMA = "legalbot.v111.phase2a.dynamic-frozen-successor-source-scope.v1"
PACKAGE_SCHEMA = "legalbot.v111.phase2a.dynamic-frozen-successor-scope-package.v1"
EXPECTED_OWNER_PACKET_CONTENT_SHA256 = (
    "fd8034b33ebfb0f6fdd6cedd2426b54e368bff9c20b408f3fbd86fb40b9f1b34"
)
EXPECTED_OWNER_APPROVAL_RECEIPT_CONTENT_SHA256 = (
    "9b47af237fe4a811b51a4c21f02db1702b71505128576fa54cbd4794e1e739fa"
)
EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256 = (
    "eb0eda2f34c8b261ea38fc9d697257cdd3bd6253c18c2d91355328c8cb78ef7b"
)
EXPECTED_ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256 = (
    "a6ea2794b276946dd24ba3d752203dd81ae14f88aae24224a80b7b62f886d539"
)
MATERIALIZATION_LEDGER_SCHEMA = "legalbot.v111.phase2a.final-remediation-materialization-ledger.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Mapping[str, Any], *, field: str) -> dict[str, Any]:
    output = dict(value)
    if field in output:
        raise ValueError("phase2a_dynamic_scope_seal_field_already_present")
    output[field] = _sha256_bytes(_canonical_json(output))
    return output


def _verify_seal(
    value: Mapping[str, Any],
    *,
    field: str,
    expected: str | None = None,
    code: str,
) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if (
        _SHA256_RE.fullmatch(supplied) is None
        or supplied != _sha256_bytes(_canonical_json(material))
        or (expected is not None and supplied != expected)
    ):
        raise ValueError(code)
    return supplied


def _load_object(path: Path, *, code: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(code)
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(code) from exc
    if not isinstance(value, dict):
        raise ValueError(code)
    return value


def _relative_review_path(settings: Settings, path: Path, *, code: str) -> str:
    review_root = (settings.evaluation_dir / "phase2a-owner-review").resolve()
    if path.is_symlink():
        raise ValueError(code)
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(review_root)
    except ValueError as exc:
        raise ValueError(code) from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(code)
    return relative.as_posix()


def _source_version_set_sha256(source_version_ids: Sequence[str]) -> str:
    unique = sorted(set(source_version_ids))
    if len(unique) != len(source_version_ids):
        raise ValueError("phase2a_dynamic_scope_duplicate_source_version")
    return _sha256_bytes(
        _canonical_json(
            {
                "schema": "legalbot.v111.phase2a.source-version-id-set.v1",
                "source_version_ids": unique,
            }
        )
    )


def source_manifest_member_identity(source: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact proposition-independent source membership identity."""

    return {
        "schema": "legalbot.v111.phase2a.source-manifest-member.v1",
        "authority_identity_id": str(source.get("authority_identity_id") or ""),
        "source_version_id": str(source.get("source_version_id") or ""),
        "document_id": str(source.get("document_id") or ""),
        "stable_identifier": str(source.get("stable_identifier") or ""),
        "content_sha256": str(source.get("content_sha256") or ""),
        "version_sha256": str(source.get("version_sha256") or ""),
        "canonical_markdown_path": str(source.get("canonical_markdown_path") or ""),
        "body_chunk_count": int(source.get("body_chunk_count") or 0),
        "scope_record_content_sha256": str(
            source.get("phase2a_scope_record_content_sha256")
            or source.get("record_content_sha256")
            or ""
        ),
    }


def source_manifest_member_sha256(source: Mapping[str, Any]) -> str:
    identity = source_manifest_member_identity(source)
    required = (
        identity["authority_identity_id"],
        identity["source_version_id"],
        identity["document_id"],
        identity["stable_identifier"],
        identity["content_sha256"],
        identity["version_sha256"],
        identity["canonical_markdown_path"],
        identity["scope_record_content_sha256"],
    )
    if (
        not all(required)
        or int(identity["body_chunk_count"]) < 1
        or any(
            _SHA256_RE.fullmatch(str(identity[field])) is None
            for field in (
                "content_sha256",
                "version_sha256",
                "scope_record_content_sha256",
            )
        )
    ):
        raise ValueError("phase2a_dynamic_scope_source_member_identity_invalid")
    return _sha256_bytes(_canonical_json(identity))


def source_manifest_member_set_sha256(sources: Sequence[Mapping[str, Any]]) -> str:
    hashes = sorted(source_manifest_member_sha256(source) for source in sources)
    if len(hashes) != len(set(hashes)):
        raise ValueError("phase2a_dynamic_scope_duplicate_source_member")
    return _sha256_bytes(
        _canonical_json(
            {
                "schema": "legalbot.v111.phase2a.source-manifest-member-set.v1",
                "member_sha256s": hashes,
            }
        )
    )


def dynamic_corpus_id(application_ledger_content_sha256: str) -> str:
    if _SHA256_RE.fullmatch(application_ledger_content_sha256) is None:
        raise ValueError("phase2a_dynamic_scope_application_ledger_digest_invalid")
    return f"{DYNAMIC_CORPUS_PREFIX}{application_ledger_content_sha256[:16]}"


def execution_chain_run_id(materialization_ledger_content_sha256: str) -> str:
    if _SHA256_RE.fullmatch(materialization_ledger_content_sha256) is None:
        raise ValueError("phase2a_dynamic_scope_materialization_digest_invalid")
    return (
        "phase2a-final-chain-"
        + _sha256_bytes(
            _canonical_json(
                {
                    "schema": "legalbot.v111.phase2a.execution-chain-identity.v1",
                    "execution_authority_content_sha256": (
                        EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
                    ),
                    "materialization_ledger_content_sha256": (
                        materialization_ledger_content_sha256
                    ),
                }
            )
        )[:16]
    )


def is_dynamic_phase2a_scope_corpus(corpus_id: str | None) -> bool:
    return DYNAMIC_CORPUS_RE.fullmatch(str(corpus_id or "")) is not None


def _verify_application_ledger(
    settings: Settings,
    path: Path,
    *,
    expected_owner_approval_receipt_content_sha256: str,
) -> tuple[dict[str, Any], str, str]:
    ledger = _load_object(path, code="phase2a_dynamic_scope_application_ledger_invalid")
    ledger_sha256 = _verify_seal(
        ledger,
        field="artifact_content_sha256",
        code="phase2a_dynamic_scope_application_ledger_seal_invalid",
    )
    if (
        ledger.get("schema") != APPLICATION_LEDGER_SCHEMA
        or ledger.get("status") != "OWNER_DECISIONS_APPLIED_POST_SCAN_BINDINGS_READY"
        or ledger.get("phase2a_owner_packet_content_sha256") != EXPECTED_OWNER_PACKET_CONTENT_SHA256
        or ledger.get("phase2a_owner_approval_receipt_content_sha256")
        != expected_owner_approval_receipt_content_sha256
        or ledger.get("original_owner_receipt_content_sha256")
        != EXPECTED_ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
        or ledger.get("execution_authority_content_sha256")
        != EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
        or _SHA256_RE.fullmatch(str(ledger.get("materialization_ledger_content_sha256") or ""))
        is None
        or ledger.get("owner_decisions_applied") is not True
        or ledger.get("exact_owner_decision_count") != 361
        or ledger.get("unresolved_owner_decision_count") != 0
        or ledger.get("material_gap_status") != "NOT_EVALUATED_UNTIL_ALL585_QUALIFICATION"
        or ledger.get("source_admission_applied") is not True
        or ledger.get("source_scan_run") is not True
        or ledger.get("successor_build_run") is not False
        or ledger.get("embedding_run") is not False
        or ledger.get("retrieval_reattestation_run") is not False
        or ledger.get("all585_qualification_run") is not False
        or ledger.get("answer_model_run") is not False
        or ledger.get("answer_release_eligible") is not False
        or ledger.get("answer_released") is not False
        or ledger.get("successor_must_remain_non_active") is not True
        or ledger.get("active_pointer_written") is not False
        or ledger.get("previous_pointer_written") is not False
        or ledger.get("phase2b_authorized") is not False
        or ledger.get("phase2b_run") is not False
        or ledger.get("development30_run") is not False
        or ledger.get("validation30_run") is not False
        or ledger.get("promotion_run") is not False
        or ledger.get("live_activation_run") is not False
        or ledger.get("training_export_run") is not False
    ):
        raise ValueError("phase2a_dynamic_scope_application_ledger_boundary_invalid")
    relative = _relative_review_path(
        settings,
        path,
        code="phase2a_dynamic_scope_application_ledger_path_invalid",
    )
    return ledger, ledger_sha256, relative


def _verify_bound_materialization_ledger(
    settings: Settings,
    path: Path,
    *,
    expected_content_sha256: str,
    expected_owner_approval_receipt_content_sha256: str,
) -> tuple[dict[str, Any], str]:
    ledger = _load_object(path, code="phase2a_dynamic_scope_materialization_ledger_invalid")
    _verify_seal(
        ledger,
        field="artifact_content_sha256",
        expected=expected_content_sha256,
        code="phase2a_dynamic_scope_materialization_ledger_seal_invalid",
    )
    packet_values = {
        str(value)
        for value in (
            ledger.get("phase2a_owner_packet_content_sha256"),
            ledger.get("final_owner_packet_content_sha256"),
        )
        if value is not None
    }
    receipt_values = {
        str(value)
        for value in (
            ledger.get("phase2a_owner_approval_receipt_content_sha256"),
            ledger.get("final_approval_receipt_content_sha256"),
        )
        if value is not None
    }
    records = ledger.get("representations")
    if (
        ledger.get("schema") != MATERIALIZATION_LEDGER_SCHEMA
        or ledger.get("status") != "OWNER_DECISIONS_APPLIED_SOURCE_MATERIALIZED_SCAN_NOT_RUN"
        or packet_values != {EXPECTED_OWNER_PACKET_CONTENT_SHA256}
        or receipt_values != {expected_owner_approval_receipt_content_sha256}
        or ledger.get("execution_authority_content_sha256")
        != EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
        or ledger.get("original_owner_receipt_content_sha256")
        != EXPECTED_ORIGINAL_OWNER_RECEIPT_CONTENT_SHA256
        or ledger.get("owner_decisions_applied") is not True
        or ledger.get("source_materialized") is not True
        or ledger.get("catalogue_mutated") is not False
        or any(
            ledger.get(field) is not False
            for field in (
                "source_scan_run",
                "successor_build_run",
                "index_built",
                "embedding_run",
                "retrieval_reattestation_run",
                "all585_qualification_run",
                "answer_model_run",
                "answer_released",
                "phase2b_run",
                "development30_run",
                "validation30_run",
                "promotion_run",
                "active_pointer_written",
                "previous_pointer_written",
                "live_activation_run",
                "training_export_run",
            )
        )
        or not isinstance(records, list)
        or ledger.get("representation_count") != len(records)
        or ledger.get("index_eligible_representation_count")
        != sum(item.get("index_eligible") is True for item in records if isinstance(item, dict))
        or ledger.get("provenance_companion_count")
        != sum(item.get("provenance_only") is True for item in records if isinstance(item, dict))
    ):
        raise ValueError("phase2a_dynamic_scope_materialization_boundary_invalid")
    identities: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("phase2a_dynamic_scope_materialization_record_invalid")
        record_sha = _verify_seal(
            record,
            field="record_content_sha256",
            code="phase2a_dynamic_scope_materialization_record_seal_invalid",
        )
        if (
            record_sha in identities
            or _SHA256_RE.fullmatch(str(record.get("content_sha256") or "")) is None
            or not record.get("authority_identity_id")
            or not record.get("owner_source_record_id")
            or record.get("index_eligible") not in {True, False}
            or record.get("provenance_only") not in {True, False}
            or bool(record["index_eligible"]) == bool(record["provenance_only"])
        ):
            raise ValueError("phase2a_dynamic_scope_materialization_record_invalid")
        identities.add(record_sha)
    relative = _relative_review_path(
        settings,
        path,
        code="phase2a_dynamic_scope_materialization_ledger_path_invalid",
    )
    return ledger, relative


def _cross_bind_application_to_materialization(
    application: Mapping[str, Any], materialization: Mapping[str, Any]
) -> None:
    included, excluded = _ledger_records(application)
    application_records = [*included, *excluded]
    materialization_records = materialization["representations"]
    by_owner_record = {
        str(record["record_content_sha256"]): record for record in materialization_records
    }
    application_owner_records = {
        str(record.get("owner_representation_record_content_sha256") or "")
        for record in application_records
    }
    if (
        len(by_owner_record) != len(materialization_records)
        or application_owner_records != set(by_owner_record)
        or len(application_records) != len(materialization_records)
    ):
        raise ValueError("phase2a_dynamic_scope_application_materialization_set_mismatch")
    for binding in application_records:
        owner_record_sha = str(binding["owner_representation_record_content_sha256"])
        materialized = by_owner_record[owner_record_sha]
        included_binding = binding.get("candidate_included") is True
        if (
            binding.get("authority_identity_id") != materialized.get("authority_identity_id")
            or binding.get("content_sha256") != materialized.get("content_sha256")
            or binding.get("owner_source_record_id") != materialized.get("owner_source_record_id")
            or included_binding is not (materialized.get("index_eligible") is True)
            or (binding.get("candidate_included") is False)
            is not (materialized.get("provenance_only") is True)
        ):
            raise ValueError("phase2a_dynamic_scope_application_materialization_binding_mismatch")
    for field in (
        "rejected_original_decision_ids",
        "rejected_original_record_ids",
        "retained_repair_hold_decision_ids",
        "retained_repair_hold_record_ids",
        "retained_original_quarantine_hold_count",
        "retained_original_identity_admission_hold_count",
        "support_crosswalk_requirement",
    ):
        if application.get(field) != materialization.get(field):
            raise ValueError("phase2a_dynamic_scope_application_hold_inventory_mismatch")
    prior_count = int(materialization.get("prior_frozen_scope_source_count") or -1)
    new_count = sum(record.get("index_eligible") is True for record in materialization_records)
    if (
        application.get("prior_frozen_scope_content_sha256")
        != materialization.get("prior_frozen_scope_content_sha256")
        or application.get("prior_frozen_scope_source_count") != prior_count
        or application.get("newly_admitted_index_source_count") != new_count
        or application.get("complete_successor_source_count") != prior_count + new_count
        or application.get("complete_successor_union_policy")
        != "EXACT_PRIOR_251_PLUS_EXACT_NEW_250"
    ):
        raise ValueError("phase2a_dynamic_scope_successor_union_contract_invalid")


def _verify_bound_complete_scan(
    database: Database,
    *,
    scan_id: str,
    scan_manifest_sha256: str,
) -> dict[str, Any]:
    if not scan_id or _SHA256_RE.fullmatch(scan_manifest_sha256) is None:
        raise ValueError("phase2a_dynamic_scope_scan_identity_invalid")
    row = database.fetchone(
        """
        SELECT id,status,expected_file_count,files_accounted,manifest_sha256,
               required_roots_json,roots_seen_json,completed_at
        FROM source_scans WHERE id=?
        """,
        (scan_id,),
    )
    if (
        row is None
        or row["status"] != "complete"
        or row["manifest_sha256"] != scan_manifest_sha256
        or int(row["expected_file_count"] or -1) < 1
        or int(row["expected_file_count"] or -1) != int(row["files_accounted"] or -2)
        or row["required_roots_json"] != row["roots_seen_json"]
        or not row["completed_at"]
    ):
        raise ValueError("phase2a_dynamic_scope_scan_not_complete_and_reconciled")
    file_count = database.fetchone(
        "SELECT COUNT(*) AS n FROM source_scan_files WHERE scan_id=?", (scan_id,)
    )
    if file_count is None or int(file_count["n"] or -1) != int(row["files_accounted"]):
        raise ValueError("phase2a_dynamic_scope_scan_file_ledger_incomplete")
    return dict(row)


def _ledger_records(
    ledger: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    included = ledger.get("included_bindings")
    excluded = ledger.get("excluded_bindings")
    if not isinstance(included, list) or not included:
        raise ValueError("phase2a_dynamic_scope_included_binding_inventory_invalid")
    if not isinstance(excluded, list):
        raise ValueError("phase2a_dynamic_scope_excluded_binding_inventory_invalid")
    if ledger.get("included_binding_count") != len(included):
        raise ValueError("phase2a_dynamic_scope_included_binding_inventory_invalid")
    if ledger.get("excluded_binding_count") != len(excluded):
        raise ValueError("phase2a_dynamic_scope_excluded_binding_inventory_invalid")

    checked_included: list[dict[str, Any]] = []
    checked_excluded: list[dict[str, Any]] = []
    binding_ids: set[str] = set()
    source_version_ids: set[str] = set()
    for record, disposition, destination in (
        *((item, "INCLUDE_IN_NON_ACTIVE_SUCCESSOR", checked_included) for item in included),
        *((item, None, checked_excluded) for item in excluded),
    ):
        if not isinstance(record, dict):
            raise ValueError("phase2a_dynamic_scope_binding_record_invalid")
        _verify_seal(
            record,
            field="record_content_sha256",
            code="phase2a_dynamic_scope_binding_record_seal_invalid",
        )
        binding_id = str(record.get("binding_id") or "")
        source_version_id = str(record.get("source_version_id") or "")
        if not binding_id or binding_id in binding_ids:
            raise ValueError("phase2a_dynamic_scope_binding_identity_invalid")
        binding_ids.add(binding_id)
        if destination is checked_included:
            if (
                record.get("disposition") != disposition
                or not source_version_id
                or source_version_id in source_version_ids
            ):
                raise ValueError("phase2a_dynamic_scope_included_binding_invalid")
            source_version_ids.add(source_version_id)
        elif (
            record.get("disposition")
            not in {"HOLD_EXCLUDE", "REJECT_EXCLUDE", "SUPERSEDED_EXCLUDE"}
            or record.get("candidate_included") is not False
        ):
            raise ValueError("phase2a_dynamic_scope_excluded_binding_invalid")
        destination.append(record)
    if set(ledger.get("included_source_version_ids") or ()) != source_version_ids:
        raise ValueError("phase2a_dynamic_scope_included_source_id_set_invalid")
    if ledger.get("included_source_version_id_set_sha256") != _source_version_set_sha256(
        tuple(source_version_ids)
    ):
        raise ValueError("phase2a_dynamic_scope_included_source_id_set_digest_invalid")
    excluded_ids = {str(record.get("source_version_id") or "") for record in checked_excluded} - {
        ""
    }
    if source_version_ids & excluded_ids:
        raise ValueError("phase2a_dynamic_scope_included_excluded_overlap")
    return checked_included, checked_excluded


def _catalogue_source(
    database: Database,
    settings: Settings,
    binding: Mapping[str, Any],
) -> dict[str, Any]:
    row = database.fetchone(
        """
        SELECT
          sv.id AS source_version_id,sv.document_id,sv.stable_identifier,
          sv.authority_identity_id,sv.title,sv.canonical_markdown_path,
          sv.version_sha256,sv.licence_name,sv.review_status,sv.superseded_by,
          sv.canonical_url,sv.source_date,sv.as_of_date,sv.created_at AS last_updated,
          sv.currentness_status,sv.metadata_json,d.status AS document_status,
          d.lane,d.subject_primary,d.jurisdiction,d.content_sha256,d.duplicate_of,
          d.retrieval_canonical,
          (SELECT COUNT(*) FROM chunks c
             WHERE c.source_version_id=sv.id AND c.stream='body') AS body_chunk_count
        FROM source_versions sv JOIN documents d ON d.id=sv.document_id
        WHERE sv.id=?
        """,
        (str(binding["source_version_id"]),),
    )
    if row is None:
        raise ValueError("phase2a_dynamic_scope_catalogue_source_missing")
    result = dict(row)
    chunks = int(result.get("body_chunk_count") or 0)
    if (
        result.get("document_id") != binding.get("document_id")
        or result.get("authority_identity_id") != binding.get("authority_identity_id")
        or result.get("content_sha256") != binding.get("content_sha256")
        or result.get("version_sha256") != binding.get("version_sha256")
        or result.get("canonical_markdown_path") != binding.get("canonical_markdown_path")
        or chunks != int(binding.get("body_chunk_count") or -1)
        or result.get("review_status") != "approved"
        or result.get("superseded_by") is not None
        or result.get("document_status") != "citable"
        or result.get("lane") != "primary_authority"
        or result.get("duplicate_of") is not None
        or int(result.get("retrieval_canonical") or 0) != 1
        or chunks < 1
    ):
        raise ValueError("phase2a_dynamic_scope_catalogue_binding_changed")
    try:
        metadata = json.loads(str(result.get("metadata_json") or "{}"))
    except json.JSONDecodeError as exc:
        raise ValueError("phase2a_dynamic_scope_catalogue_metadata_invalid") from exc
    if (
        not isinstance(metadata, dict)
        or metadata.get("eligible_for_model_use") is not True
        or metadata.get("ai_use_policy") == "prohibited"
    ):
        raise ValueError("phase2a_dynamic_scope_source_not_index_eligible")
    markdown = settings.project_root / str(result["canonical_markdown_path"])
    if markdown.is_symlink() or not markdown.is_file() or markdown.stat().st_size < 1:
        raise ValueError("phase2a_dynamic_scope_canonical_markdown_unavailable")
    result["body_chunk_count"] = chunks
    result["unfiltered_body_chunk_count"] = chunks
    result["phase2a_source_kind"] = str(binding.get("source_kind") or "")
    result["phase2a_scope_record_content_sha256"] = str(binding.get("record_content_sha256") or "")
    result["answer_release_eligible_in_successor"] = False
    return result


def _frozen_source_record(row: Mapping[str, Any], binding: Mapping[str, Any]) -> dict[str, Any]:
    value = {
        "binding_id": binding["binding_id"],
        "source_version_id": row["source_version_id"],
        "document_id": row["document_id"],
        "stable_identifier": row["stable_identifier"],
        "authority_identity_id": row["authority_identity_id"],
        "content_sha256": row["content_sha256"],
        "version_sha256": row["version_sha256"],
        "canonical_markdown_path": row["canonical_markdown_path"],
        "body_chunk_count": int(row["body_chunk_count"]),
        "source_kind": binding.get("source_kind"),
        "answer_release_eligible_in_successor": False,
    }
    return _sealed(value, field="record_content_sha256")


def _prior_frozen_source_record(row: Mapping[str, Any]) -> dict[str, Any]:
    value = {
        "binding_id": f"prior-frozen:{row['source_version_id']}",
        "source_version_id": row["source_version_id"],
        "document_id": row["document_id"],
        "stable_identifier": row["stable_identifier"],
        "authority_identity_id": row["authority_identity_id"],
        "content_sha256": row["content_sha256"],
        "version_sha256": row["version_sha256"],
        "canonical_markdown_path": row["canonical_markdown_path"],
        "body_chunk_count": int(row["body_chunk_count"]),
        "source_kind": "PRIOR_FROZEN_SCOPE",
        "answer_release_eligible_in_successor": False,
    }
    return _sealed(value, field="record_content_sha256")


def _verify_prior_candidate(
    settings: Settings,
    database: Database,
    *,
    build_id: str,
    expected_source_version_ids: Sequence[str],
) -> dict[str, Any]:
    build = database.fetchone(
        """
        SELECT id,corpus_id,status,stage,document_count,chunk_count,vector_count,
               failure_reason_code FROM index_builds WHERE id=?
        """,
        (build_id,),
    )
    manifest_path = settings.index_dir / "builds" / build_id / "approved-source-manifest.json"
    manifest = _load_object(
        manifest_path,
        code="phase2a_dynamic_scope_prior_candidate_manifest_invalid",
    )
    manifest_sources = manifest.get("sources")
    manifest_source_ids = (
        [str(item.get("source_version_id") or "") for item in manifest_sources]
        if isinstance(manifest_sources, list)
        else []
    )
    expected_ids = list(expected_source_version_ids)
    if (
        build is None
        or build["status"] != "built_unscored"
        or build["stage"] != "built_unscored"
        or build["failure_reason_code"] not in (None, "")
        or int(build["document_count"] or 0) != len(expected_ids)
        or int(build["chunk_count"] or 0) < 1
        or int(build["chunk_count"] or 0) != int(build["vector_count"] or -1)
        or manifest.get("source_count") != len(expected_ids)
        or manifest.get("successor_must_remain_non_active") is not True
        or manifest.get("answer_release_eligible") is not False
        or set(manifest_source_ids) != set(expected_ids)
        or len(manifest_source_ids) != len(set(manifest_source_ids))
    ):
        raise ValueError("phase2a_dynamic_scope_prior_candidate_binding_changed")
    return {
        "build_id": build_id,
        "corpus_id": str(build["corpus_id"] or ""),
        "source_manifest_file_sha256": _sha256_file(manifest_path),
        "source_manifest_content_sha256": str(manifest.get("manifest_sha256") or ""),
        "source_count": len(expected_ids),
        "chunk_count": int(build["chunk_count"]),
    }


def freeze_dynamic_phase2a_scope(
    settings: Settings,
    database: Database,
    *,
    owner_approval_receipt_path: Path,
    owner_approval_receipt_content_sha256: str,
    application_ledger_path: Path,
    materialization_ledger_path: Path,
    output_root: Path,
    predecessor_build_id: str,
    source_root_inventory_content_sha256: str,
) -> dict[str, Any]:
    """Freeze the exact post-scan source rows named by an application ledger."""

    if (
        _SHA256_RE.fullmatch(owner_approval_receipt_content_sha256) is None
        or _SHA256_RE.fullmatch(source_root_inventory_content_sha256) is None
        or not predecessor_build_id
    ):
        raise ValueError("phase2a_dynamic_scope_input_identity_invalid")
    owner_receipt = _load_object(
        owner_approval_receipt_path,
        code="phase2a_dynamic_scope_owner_approval_receipt_invalid",
    )
    _verify_seal(
        owner_receipt,
        field="artifact_content_sha256",
        expected=owner_approval_receipt_content_sha256,
        code="phase2a_dynamic_scope_owner_approval_receipt_seal_invalid",
    )
    if (
        owner_receipt.get("final_owner_packet_content_sha256")
        != EXPECTED_OWNER_PACKET_CONTENT_SHA256
        or owner_receipt.get("owner_approved") is not True
        or owner_receipt.get("owner_adoption_recorded") is not True
        or owner_receipt.get("complete_source_scan_authorized") is not True
        or owner_receipt.get("successor_build_authorized") is not True
        or owner_receipt.get("embedding_authorized") is not True
        or owner_receipt.get("active_pointer_write_authorized") is not False
        or owner_receipt.get("previous_pointer_write_authorized") is not False
        or owner_receipt.get("answer_model_authorized") is not False
        or owner_receipt.get("phase2b_authorized") is not False
    ):
        raise ValueError("phase2a_dynamic_scope_owner_approval_boundary_invalid")
    owner_receipt_relative = _relative_review_path(
        settings,
        owner_approval_receipt_path,
        code="phase2a_dynamic_scope_owner_approval_receipt_path_invalid",
    )
    ledger, ledger_sha256, ledger_relative = _verify_application_ledger(
        settings,
        application_ledger_path,
        expected_owner_approval_receipt_content_sha256=owner_approval_receipt_content_sha256,
    )
    materialization, materialization_relative = _verify_bound_materialization_ledger(
        settings,
        materialization_ledger_path,
        expected_content_sha256=str(ledger["materialization_ledger_content_sha256"]),
        expected_owner_approval_receipt_content_sha256=(owner_approval_receipt_content_sha256),
    )
    _cross_bind_application_to_materialization(ledger, materialization)
    scan = _verify_bound_complete_scan(
        database,
        scan_id=str(ledger.get("source_scan_id") or ""),
        scan_manifest_sha256=str(ledger.get("source_scan_manifest_sha256") or ""),
    )
    included, excluded = _ledger_records(ledger)
    new_rows = [_catalogue_source(database, settings, binding) for binding in included]
    new_sources = [
        _frozen_source_record(row, binding) for row, binding in zip(new_rows, included, strict=True)
    ]
    prior_scope = load_phase2a_frozen_scope(settings)
    prior_rows, selected_prior_scope = select_phase2a_frozen_scope_rows(
        database,
        settings,
        corpus_id=PRIOR_PHASE2A_CORPUS_ID,
        max_chunks=None,
        preferred_small_first=False,
    )
    if selected_prior_scope["scope_content_sha256"] != prior_scope["scope_content_sha256"]:
        raise ValueError("phase2a_dynamic_scope_prior_scope_binding_changed")
    prior_sources = [_prior_frozen_source_record(row) for row in prior_rows]
    prior_candidate = _verify_prior_candidate(
        settings,
        database,
        build_id=predecessor_build_id,
        expected_source_version_ids=[str(source["source_version_id"]) for source in prior_sources],
    )
    prior_authorities = {str(source["authority_identity_id"]) for source in prior_sources}
    new_authorities = {str(source["authority_identity_id"]) for source in new_sources}
    if prior_authorities & new_authorities:
        raise ValueError("phase2a_dynamic_scope_prior_new_authority_overlap")
    sources = [*prior_sources, *new_sources]
    source_version_ids = [str(source["source_version_id"]) for source in sources]
    if len(set(source_version_ids)) != len(source_version_ids):
        raise ValueError("phase2a_dynamic_scope_duplicate_source_version")
    chunk_count = sum(int(source["body_chunk_count"]) for source in sources)
    family_counts = Counter(str(source.get("source_kind") or "") for source in sources)
    corpus_id = dynamic_corpus_id(ledger_sha256)
    scope = _sealed(
        {
            "schema": SCOPE_SCHEMA,
            "status": "OWNER_APPROVED_NON_ACTIVE_SUCCESSOR_SCOPE_FROZEN",
            "corpus_id": corpus_id,
            "phase2a_owner_packet_content_sha256": EXPECTED_OWNER_PACKET_CONTENT_SHA256,
            "phase2a_owner_approval_receipt_content_sha256": (
                owner_approval_receipt_content_sha256
            ),
            "phase2a_owner_approval_receipt_relative_path": owner_receipt_relative,
            "phase2a_owner_application_ledger_content_sha256": ledger_sha256,
            "phase2a_owner_application_ledger_relative_path": ledger_relative,
            "phase2a_execution_authority_content_sha256": (
                EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
            ),
            "materialization_ledger_content_sha256": materialization["artifact_content_sha256"],
            "materialization_ledger_relative_path": materialization_relative,
            "execution_chain_run_id": execution_chain_run_id(
                str(materialization["artifact_content_sha256"])
            ),
            "source_root_inventory_content_sha256": source_root_inventory_content_sha256,
            "source_scan_id": scan["id"],
            "source_scan_manifest_sha256": scan["manifest_sha256"],
            "source_scan_expected_file_count": int(scan["expected_file_count"]),
            "source_scan_files_accounted": int(scan["files_accounted"]),
            "predecessor_build_id": predecessor_build_id,
            "predecessor_source_manifest_content_sha256": prior_candidate[
                "source_manifest_content_sha256"
            ],
            "predecessor_source_manifest_file_sha256": prior_candidate[
                "source_manifest_file_sha256"
            ],
            "predecessor_scope_content_sha256": prior_scope["scope_content_sha256"],
            "prior_source_count": len(prior_sources),
            "newly_admitted_source_count": len(new_sources),
            "source_count": len(sources),
            "chunk_count": chunk_count,
            "source_version_id_set_sha256": _source_version_set_sha256(source_version_ids),
            "source_family_counts": dict(sorted(family_counts.items())),
            "excluded_source_binding_count": len(excluded),
            "selection_policy": "exact-owner-approved-dynamic-phase2a-successor-scope",
            "sources": sources,
            "answer_release_eligible": False,
            "successor_must_remain_non_active": True,
            "common_legal_currentness_cutoff": None,
            "active_or_previous_write_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "promotion_authorized": False,
        },
        field="scope_content_sha256",
    )
    if output_root.exists() or output_root.is_symlink():
        raise FileExistsError("phase2a_dynamic_scope_output_exists")
    output_root.mkdir(parents=True, mode=0o700)
    scope_path = output_root / SCOPE_FILENAME
    scope_path.write_bytes(_pretty_json(scope))
    os.chmod(scope_path, 0o600)
    package = _sealed(
        {
            "schema": PACKAGE_SCHEMA,
            "status": "DYNAMIC_PHASE2A_SCOPE_FROZEN_BUILD_NOT_STARTED",
            "corpus_id": corpus_id,
            "scope_content_sha256": scope["scope_content_sha256"],
            "scope_file_sha256": _sha256_file(scope_path),
            "source_count": len(sources),
            "chunk_count": chunk_count,
            "source_version_id_set_sha256": scope["source_version_id_set_sha256"],
            "phase2a_owner_packet_content_sha256": EXPECTED_OWNER_PACKET_CONTENT_SHA256,
            "phase2a_owner_approval_receipt_content_sha256": (
                owner_approval_receipt_content_sha256
            ),
            "phase2a_owner_application_ledger_content_sha256": ledger_sha256,
            "phase2a_execution_authority_content_sha256": (
                EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
            ),
            "materialization_ledger_content_sha256": materialization["artifact_content_sha256"],
            "execution_chain_run_id": execution_chain_run_id(
                str(materialization["artifact_content_sha256"])
            ),
            "source_scan_id": scan["id"],
            "source_scan_manifest_sha256": scan["manifest_sha256"],
            "answer_release_eligible": False,
            "successor_must_remain_non_active": True,
            "candidate_build_started": False,
            "active_or_previous_written": False,
            "phase2b_authorized": False,
        },
        field="package_content_sha256",
    )
    package_path = output_root / PACKAGE_FILENAME
    package_path.write_bytes(_pretty_json(package))
    os.chmod(package_path, 0o600)
    return {
        "scope": scope,
        "package": package,
        "scope_path": scope_path,
        "package_path": package_path,
    }


def _scope_candidates(settings: Settings, corpus_id: str) -> list[Path]:
    review_root = settings.evaluation_dir / "phase2a-owner-review"
    if review_root.is_symlink() or not review_root.is_dir():
        raise ValueError("phase2a_dynamic_scope_review_root_invalid")
    candidates: list[Path] = []
    for path in review_root.glob(f"*/{SCOPE_FILENAME}"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            value = json.loads(path.read_bytes())
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("corpus_id") == corpus_id:
            candidates.append(path)
    return sorted(candidates)


def load_dynamic_phase2a_scope(settings: Settings, corpus_id: str) -> dict[str, Any]:
    if not is_dynamic_phase2a_scope_corpus(corpus_id):
        raise ValueError("phase2a_dynamic_scope_corpus_invalid")
    candidates = _scope_candidates(settings, corpus_id)
    if len(candidates) != 1:
        raise ValueError("phase2a_dynamic_scope_not_unique")
    scope_path = candidates[0]
    package_path = scope_path.with_name(PACKAGE_FILENAME)
    scope = _load_object(scope_path, code="phase2a_dynamic_scope_invalid")
    package = _load_object(package_path, code="phase2a_dynamic_scope_package_invalid")
    scope_sha256 = _verify_seal(
        scope,
        field="scope_content_sha256",
        code="phase2a_dynamic_scope_seal_invalid",
    )
    package_sha256 = _verify_seal(
        package,
        field="package_content_sha256",
        code="phase2a_dynamic_scope_package_seal_invalid",
    )
    sources = scope.get("sources")
    if (
        scope.get("schema") != SCOPE_SCHEMA
        or scope.get("status") != "OWNER_APPROVED_NON_ACTIVE_SUCCESSOR_SCOPE_FROZEN"
        or scope.get("corpus_id") != corpus_id
        or scope.get("phase2a_owner_packet_content_sha256") != EXPECTED_OWNER_PACKET_CONTENT_SHA256
        or not _SHA256_RE.fullmatch(
            str(scope.get("phase2a_owner_approval_receipt_content_sha256") or "")
        )
        or not _SHA256_RE.fullmatch(
            str(scope.get("phase2a_owner_application_ledger_content_sha256") or "")
        )
        or scope.get("phase2a_execution_authority_content_sha256")
        != EXPECTED_EXECUTION_AUTHORITY_CONTENT_SHA256
        or not _SHA256_RE.fullmatch(str(scope.get("materialization_ledger_content_sha256") or ""))
        or scope.get("execution_chain_run_id")
        != execution_chain_run_id(str(scope.get("materialization_ledger_content_sha256") or ""))
        or not _SHA256_RE.fullmatch(str(scope.get("source_root_inventory_content_sha256") or ""))
        or scope.get("answer_release_eligible") is not False
        or scope.get("successor_must_remain_non_active") is not True
        or scope.get("active_or_previous_write_authorized") is not False
        or scope.get("phase2b_authorized") is not False
        or scope.get("development30_authorized") is not False
        or scope.get("validation30_authorized") is not False
        or scope.get("promotion_authorized") is not False
        or not isinstance(sources, list)
        or not sources
    ):
        raise ValueError("phase2a_dynamic_scope_boundary_invalid")
    source_version_ids: list[str] = []
    chunks = 0
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError("phase2a_dynamic_scope_source_invalid")
        _verify_seal(
            source,
            field="record_content_sha256",
            code="phase2a_dynamic_scope_source_seal_invalid",
        )
        source_id = str(source.get("source_version_id") or "")
        if (
            not source_id
            or source_id in source_version_ids
            or source.get("answer_release_eligible_in_successor") is not False
            or int(source.get("body_chunk_count") or 0) < 1
        ):
            raise ValueError("phase2a_dynamic_scope_source_identity_invalid")
        source_version_ids.append(source_id)
        chunks += int(source["body_chunk_count"])
    if (
        scope.get("source_count") != len(sources)
        or scope.get("chunk_count") != chunks
        or scope.get("source_version_id_set_sha256")
        != _source_version_set_sha256(source_version_ids)
        or dynamic_corpus_id(str(scope["phase2a_owner_application_ledger_content_sha256"]))
        != corpus_id
    ):
        raise ValueError("phase2a_dynamic_scope_inventory_invalid")
    if (
        package.get("schema") != PACKAGE_SCHEMA
        or package.get("status") != "DYNAMIC_PHASE2A_SCOPE_FROZEN_BUILD_NOT_STARTED"
        or package.get("corpus_id") != corpus_id
        or package.get("scope_content_sha256") != scope_sha256
        or package.get("scope_file_sha256") != _sha256_file(scope_path)
        or package.get("source_count") != scope["source_count"]
        or package.get("chunk_count") != scope["chunk_count"]
        or package.get("source_version_id_set_sha256") != scope["source_version_id_set_sha256"]
        or package.get("phase2a_owner_packet_content_sha256")
        != scope["phase2a_owner_packet_content_sha256"]
        or package.get("phase2a_owner_approval_receipt_content_sha256")
        != scope["phase2a_owner_approval_receipt_content_sha256"]
        or package.get("phase2a_owner_application_ledger_content_sha256")
        != scope["phase2a_owner_application_ledger_content_sha256"]
        or package.get("phase2a_execution_authority_content_sha256")
        != scope["phase2a_execution_authority_content_sha256"]
        or package.get("materialization_ledger_content_sha256")
        != scope["materialization_ledger_content_sha256"]
        or package.get("execution_chain_run_id") != scope["execution_chain_run_id"]
        or package.get("source_scan_id") != scope["source_scan_id"]
        or package.get("source_scan_manifest_sha256") != scope["source_scan_manifest_sha256"]
        or package.get("answer_release_eligible") is not False
        or package.get("successor_must_remain_non_active") is not True
        or package.get("candidate_build_started") is not False
        or package.get("active_or_previous_written") is not False
        or package.get("phase2b_authorized") is not False
        or not package_sha256
    ):
        raise ValueError("phase2a_dynamic_scope_package_boundary_invalid")
    return scope


def _verify_scope_scan(database: Database, scope: Mapping[str, Any]) -> None:
    _verify_bound_complete_scan(
        database,
        scan_id=str(scope["source_scan_id"]),
        scan_manifest_sha256=str(scope["source_scan_manifest_sha256"]),
    )


def select_dynamic_phase2a_scope_rows(
    database: Database,
    settings: Settings,
    *,
    corpus_id: str,
    max_chunks: int | None,
    preferred_small_first: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if max_chunks is not None or preferred_small_first:
        raise ValueError("phase2a_dynamic_scope_cannot_be_reordered_or_truncated")
    scope = load_dynamic_phase2a_scope(settings, corpus_id)
    _verify_scope_scan(database, scope)
    selected: list[dict[str, Any]] = []
    for frozen in scope["sources"]:
        binding = {
            **frozen,
            "source_kind": frozen.get("source_kind"),
        }
        selected.append(_catalogue_source(database, settings, binding))
    if (
        len(selected) != scope["source_count"]
        or sum(int(row["body_chunk_count"]) for row in selected) != scope["chunk_count"]
        or _source_version_set_sha256([str(row["source_version_id"]) for row in selected])
        != scope["source_version_id_set_sha256"]
    ):
        raise ValueError("phase2a_dynamic_scope_catalogue_inventory_changed")
    return selected, scope


__all__ = [
    "APPLICATION_LEDGER_SCHEMA",
    "DYNAMIC_CORPUS_PREFIX",
    "PACKAGE_FILENAME",
    "SCOPE_FILENAME",
    "dynamic_corpus_id",
    "execution_chain_run_id",
    "freeze_dynamic_phase2a_scope",
    "is_dynamic_phase2a_scope_corpus",
    "load_dynamic_phase2a_scope",
    "select_dynamic_phase2a_scope_rows",
    "source_manifest_member_identity",
    "source_manifest_member_set_sha256",
    "source_manifest_member_sha256",
]
