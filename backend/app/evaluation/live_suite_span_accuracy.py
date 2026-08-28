"""Exact-match checks for spans the owner actually uses.

AI is not a legal reviewer. It only confirms that a bound source_version_id,
chunk_id, locator and content hash match the local catalogue or an accepted
repair span with 100% equality. Any mismatch fails closed. v1 repair spans are
rejected as new gold.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .live30 import assert_safe_evaluation_payload
from .live_suite_repair_span import (
    IPFDA_DOTS_PARENT,
    REPAIR_SPAN_SCHEMA_V2,
    computed_repair_span_id,
    identity_complete,
    is_v1_repair_span,
)

SPAN_ACCURACY_SCHEMA = "legalbot.live60-user-span-accuracy.v1"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _repair_item(repair: Mapping[str, Any] | None, chunk_id: str) -> Mapping[str, Any] | None:
    for item in (repair or {}).get("repairs", ()):
        if not isinstance(item, Mapping):
            continue
        if item.get("repair_span_id") == chunk_id:
            return item
    return None


def _mismatch(found: Mapping[str, Any], claimed: Any, field: str) -> str | None:
    if claimed in (None, ""):
        return None
    if str(found.get(field) or "") != str(claimed):
        return f"{field}_mismatch"
    return None


def check_user_span_exact_match(
    *,
    chunk_id: str,
    content_sha256: str,
    legal_locator: str,
    source_version_id: str | None = None,
    catalog_path: Path | None = None,
    repair: Mapping[str, Any] | None = None,
    require_gold_eligible: bool = True,
    legal_authority_id: str | None = None,
    parent_chunk_id: str | None = None,
    legal_role: str | None = None,
    official_snapshot_sha256: str | None = None,
    derivation_manifest_sha256: str | None = None,
    stable_source_id: str | None = None,
    source_type: str | None = None,
    jurisdiction: str | None = None,
) -> dict[str, Any]:
    """Return an exact-match report. Never seals gold."""

    mismatches: list[str] = []
    derived_source_version_id: str | None = source_version_id
    derived_locator: str | None = legal_locator
    derived_content_sha256: str | None = content_sha256
    derived_legal_authority_id: str | None = legal_authority_id
    derived_jurisdiction: str | None = jurisdiction
    if chunk_id.startswith("repair-span-"):
        found = _repair_item(repair, chunk_id)
        if found is None:
            mismatches.append("repair_span_absent")
        else:
            if is_v1_repair_span(found) and require_gold_eligible:
                mismatches.append("repair_span_v1_rejected_as_new_gold")
            computed = _sha256_text(str(found.get("markdown_text") or ""))
            if found.get("text_sha256") != computed:
                mismatches.append("repair_hash_not_self_consistent")
            if found.get("text_sha256") != content_sha256 or computed != content_sha256:
                mismatches.append("content_sha256_mismatch")
            if found.get("required_sublocator") != legal_locator:
                mismatches.append("legal_locator_mismatch")
            if require_gold_eligible and found.get("gold_eligible_candidate") is not True:
                mismatches.append("repair_span_not_gold_eligible")
            if (
                require_gold_eligible
                and str(found.get("parent_chunk_id") or "") == IPFDA_DOTS_PARENT
            ):
                mismatches.append("dots_only_ipfda_parent_excluded")
            if found.get("schema") == REPAIR_SPAN_SCHEMA_V2:
                if computed_repair_span_id(found) != str(found.get("repair_span_id") or ""):
                    mismatches.append("repair_span_id_mismatch")
                if require_gold_eligible and not identity_complete(found):
                    mismatches.append("repair_identity_incomplete")
                for field, claimed in (
                    ("source_version_id", source_version_id),
                    ("legal_authority_id", legal_authority_id),
                    ("parent_chunk_id", parent_chunk_id),
                    ("role", legal_role),
                    ("official_snapshot_sha256", official_snapshot_sha256),
                    ("derivation_manifest_sha256", derivation_manifest_sha256),
                    ("stable_source_id", stable_source_id),
                    ("source_type", source_type),
                    ("jurisdiction", jurisdiction),
                    ("legal_locator", legal_locator),
                ):
                    code = _mismatch(found, claimed, field)
                    if code:
                        mismatches.append(code)
            if found is not None:
                derived_source_version_id = str(found.get("source_version_id") or "") or None
                derived_locator = (
                    str(found.get("required_sublocator") or found.get("legal_locator") or "")
                    or None
                )
                derived_content_sha256 = str(found.get("text_sha256") or "") or None
                derived_legal_authority_id = str(found.get("legal_authority_id") or "") or None
                derived_jurisdiction = str(found.get("jurisdiction") or "") or jurisdiction
    elif catalog_path is None or not catalog_path.is_file():
        mismatches.append("catalogue_absent")
    else:
        connection = sqlite3.connect(f"file:{catalog_path}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                """
                SELECT c.id, c.source_version_id, c.locator, c.text_sha256, c.markdown_text,
                       sv.authority_identity_id, d.content_sha256 AS official_snapshot_sha256
                FROM chunks c
                LEFT JOIN source_versions sv ON sv.id = c.source_version_id
                LEFT JOIN documents d ON d.id = sv.document_id
                WHERE c.id = ?
                """,
                (chunk_id,),
            ).fetchone()
        except sqlite3.OperationalError:
            row = connection.execute(
                """
                SELECT id, source_version_id, locator, text_sha256, markdown_text
                FROM chunks WHERE id = ?
                """,
                (chunk_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            mismatches.append("chunk_absent")
        else:
            computed = _sha256_text(row["markdown_text"])
            if row["text_sha256"] != computed:
                mismatches.append("catalogue_hash_not_self_consistent")
            if row["text_sha256"] != content_sha256 or computed != content_sha256:
                mismatches.append("content_sha256_mismatch")
            if source_version_id and row["source_version_id"] != source_version_id:
                mismatches.append("source_version_id_mismatch")
            catalog_locator = str(row["locator"] or "").strip()
            bound_locator = str(legal_locator).strip()
            if not bound_locator:
                mismatches.append("legal_locator_empty")
            elif catalog_locator and catalog_locator != bound_locator:
                mismatches.append("legal_locator_mismatch")
            keys = set(row.keys())
            if (
                legal_authority_id
                and "authority_identity_id" in keys
                and str(row["authority_identity_id"] or "") != legal_authority_id
            ):
                mismatches.append("legal_authority_id_mismatch")
            if (
                official_snapshot_sha256
                and "official_snapshot_sha256" in keys
                and str(row["official_snapshot_sha256"] or "") != official_snapshot_sha256
            ):
                mismatches.append("official_snapshot_sha256_mismatch")
            derived_source_version_id = str(row["source_version_id"] or "")
            derived_locator = str(row["locator"] or "")
            derived_content_sha256 = str(row["text_sha256"] or "")
            derived_legal_authority_id = (
                str(row["authority_identity_id"] or "") if "authority_identity_id" in keys else None
            )
            derived_jurisdiction = jurisdiction
    hash_passed = "content_sha256_mismatch" not in mismatches and (
        "catalogue_absent" not in mismatches and "repair_span_absent" not in mismatches
    )
    locator_passed = "legal_locator_mismatch" not in mismatches and hash_passed
    identity_passed = (
        not any(
            code.endswith("_mismatch") and "locator" not in code and "content_sha256" not in code
            for code in mismatches
        )
        and "catalogue_absent" not in mismatches
        and "repair_span_absent" not in mismatches
    )
    if not mismatches:
        identity_passed = True
        hash_passed = True
        locator_passed = True
    jurisdiction_passed = "jurisdiction_mismatch" not in mismatches and (
        "catalogue_absent" not in mismatches
    )
    payload = {
        "schema": SPAN_ACCURACY_SCHEMA,
        "chunk_id": chunk_id,
        "content_sha256": content_sha256,
        "legal_locator": legal_locator,
        "exact_match": not mismatches,
        "mismatch_codes": mismatches,
        "identity_passed": bool(not mismatches and identity_passed),
        "hash_passed": bool(not mismatches and hash_passed),
        "locator_passed": bool(not mismatches and locator_passed),
        "jurisdiction_passed": bool(not mismatches and jurisdiction_passed),
        "derived_source_version_id": derived_source_version_id,
        "derived_locator": derived_locator,
        "derived_content_sha256": derived_content_sha256,
        "derived_legal_authority_id": derived_legal_authority_id,
        "derived_jurisdiction": derived_jurisdiction,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "seals_expert_gold": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    assert_safe_evaluation_payload(payload)
    return payload


def verify_user_span_exact_match(
    *,
    chunk_id: str,
    content_sha256: str,
    legal_locator: str,
    source_version_id: str | None = None,
    catalog_path: Path | None = None,
    repair: Mapping[str, Any] | None = None,
    require_gold_eligible: bool = True,
    legal_authority_id: str | None = None,
    parent_chunk_id: str | None = None,
    legal_role: str | None = None,
    official_snapshot_sha256: str | None = None,
    derivation_manifest_sha256: str | None = None,
    stable_source_id: str | None = None,
    source_type: str | None = None,
    jurisdiction: str | None = None,
) -> dict[str, Any]:
    """Fail closed unless every bound identity matches local bytes exactly."""

    payload = check_user_span_exact_match(
        chunk_id=chunk_id,
        content_sha256=content_sha256,
        legal_locator=legal_locator,
        source_version_id=source_version_id,
        catalog_path=catalog_path,
        repair=repair,
        require_gold_eligible=require_gold_eligible,
        legal_authority_id=legal_authority_id,
        parent_chunk_id=parent_chunk_id,
        legal_role=legal_role,
        official_snapshot_sha256=official_snapshot_sha256,
        derivation_manifest_sha256=derivation_manifest_sha256,
        stable_source_id=stable_source_id,
        source_type=source_type,
        jurisdiction=jurisdiction,
    )
    if not payload["exact_match"]:
        raise ValueError("user-bound span failed exact-match accuracy check")
    return payload


def verify_overlay_spans_exact_match(
    qualification: Any,
    *,
    catalog_path: Path | None = None,
    repair: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Exact-match every span the sealed overlay actually uses."""

    spans: list[Any] = []
    for case in qualification.cases:
        spans.extend(case.exact_gold_spans)
    reports = [
        verify_user_span_exact_match(
            chunk_id=span.chunk_id,
            content_sha256=span.content_sha256,
            legal_locator=span.legal_locator,
            source_version_id=span.source_version_id,
            catalog_path=catalog_path,
            repair=repair,
            legal_authority_id=span.legal_authority_id,
            legal_role=span.legal_role,
        )
        for span in spans
    ]
    payload = {
        "schema": SPAN_ACCURACY_SCHEMA,
        "bound_span_count": len(spans),
        "exact_match": True,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "seals_expert_gold": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
        "checked_chunk_ids": [span.chunk_id for span in spans],
        "reports": reports,
    }
    assert_safe_evaluation_payload(
        {key: value for key, value in payload.items() if key != "reports"}
    )
    return payload


def verify_user_used_spans(
    *,
    ticks: Mapping[str, Any] | None = None,
    repair: Mapping[str, Any] | None = None,
    catalog_path: Path | None = None,
) -> dict[str, Any]:
    """Exact-match repair spans and any issue spans the owner has bound."""

    mismatches: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []
    for item in (repair or {}).get("repairs", ()):
        report = check_user_span_exact_match(
            chunk_id=str(item["repair_span_id"]),
            content_sha256=str(item["text_sha256"]),
            legal_locator=str(item["required_sublocator"]),
            source_version_id=item.get("source_version_id"),
            legal_authority_id=item.get("legal_authority_id"),
            parent_chunk_id=item.get("parent_chunk_id"),
            legal_role=item.get("role"),
            official_snapshot_sha256=item.get("official_snapshot_sha256"),
            derivation_manifest_sha256=item.get("derivation_manifest_sha256"),
            stable_source_id=item.get("stable_source_id"),
            source_type=item.get("source_type"),
            jurisdiction=item.get("jurisdiction"),
            repair=repair,
            require_gold_eligible=bool(item.get("gold_eligible_candidate")),
        )
        checked.append(report)
        if not report["exact_match"]:
            mismatches.append(report)
    bound_issue_spans = 0
    for case in (ticks or {}).get("cases", ()):
        for issue in case.get("issues", ()):
            for span in issue.get("exact_gold_spans", ()):
                bound_issue_spans += 1
                report = check_user_span_exact_match(
                    chunk_id=str(span["chunk_id"]),
                    content_sha256=str(span["content_sha256"]),
                    legal_locator=str(span["legal_locator"]),
                    source_version_id=span.get("source_version_id"),
                    legal_authority_id=span.get("legal_authority_id"),
                    parent_chunk_id=span.get("parent_chunk_id"),
                    legal_role=span.get("legal_role") or span.get("role"),
                    official_snapshot_sha256=span.get("official_snapshot_sha256"),
                    derivation_manifest_sha256=span.get("derivation_manifest_sha256"),
                    catalog_path=catalog_path,
                    repair=repair,
                )
                checked.append(report)
                if not report["exact_match"]:
                    mismatches.append(report)
    payload = {
        "schema": SPAN_ACCURACY_SCHEMA,
        "ai_role": "mechanical_accuracy_verifier_only",
        "ai_second_reviewer_forbidden": True,
        "owner_is_primary_reviewer": True,
        "checked_span_count": len(checked),
        "bound_issue_span_count": bound_issue_spans,
        "repair_span_count": len((repair or {}).get("repairs", ())),
        "exact_match": not mismatches,
        "mismatch_count": len(mismatches),
        "mismatch_codes": [
            code for report in mismatches for code in report.get("mismatch_codes", ())
        ],
        "seals_expert_gold": False,
        "overlay_sealable": False,
        "generation_authorised": False,
        "eligible_for_training": False,
        "training_export_allowed": False,
    }
    assert_safe_evaluation_payload(payload)
    if mismatches:
        raise ValueError("user-used spans failed 100% exact-match accuracy check")
    return payload
