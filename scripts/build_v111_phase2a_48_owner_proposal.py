#!/usr/bin/env python3
"""Build one exact owner proposal for 48 verified Phase-2A span packets.

The proposal is non-authoritative until the owner replies exactly ``OK`` to
its sealed approval payload.  Even then, the scope is limited to internal-tool
proposition/span decisions and continued Phase-2A remediation.  Source
admission, candidate mutation, Phase 2B and Development 30 remain excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

HISTORICAL_SCHEMA = "legalbot.live60.owner-reviewed-search-answers.v1"
SPAN_BATCH_SCHEMA = "legalbot.v111.phase2a.candidate-span-owner-review-batch.v1"
FRESH_SCHEMA = "legalbot.v111.phase2a.fresh-official-candidate-span-verification.v1"
SNAPSHOT_SCHEMA = "legalbot.v111-phase2a-canonical-registry-snapshot.v1"
EXPECTED_ITEM_COUNT = 48
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_48_owner_proposal_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_48_owner_proposal_input_must_be_object")
    return value


def _verify_seal(value: dict[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_exclusive(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def build_proposal(
    *,
    historical_path: Path,
    span_batch_path: Path,
    fresh_verification_path: Path,
    snapshot_path: Path,
    output_root: Path,
    owner_typed_name: str,
    owner_decision_date: str,
) -> dict[str, Any]:
    """Create the exact 48-row owner proposal without applying it."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_48_owner_proposal_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_48_owner_proposal_output_mode_invalid")
    if not owner_typed_name.strip() or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", owner_decision_date):
        raise ValueError("phase2a_48_owner_proposal_owner_identity_invalid")

    historical = _load_json(historical_path)
    historical_records = historical.get("records")
    if historical.get("schema") != HISTORICAL_SCHEMA or not isinstance(historical_records, list):
        raise ValueError("phase2a_48_owner_proposal_historical_invalid")
    historical_by_row = {
        str(record.get("issue_key") or ""): record
        for record in historical_records
        if isinstance(record, dict)
    }

    span_batch = _load_json(span_batch_path)
    span_batch_sha256 = _verify_seal(
        span_batch,
        "batch_content_sha256",
        "phase2a_48_owner_proposal_span_batch_seal_invalid",
    )
    span_items = span_batch.get("items")
    if (
        span_batch.get("schema") != SPAN_BATCH_SCHEMA
        or not isinstance(span_items, list)
        or len(span_items) != EXPECTED_ITEM_COUNT
    ):
        raise ValueError("phase2a_48_owner_proposal_span_batch_invalid")

    fresh = _load_json(fresh_verification_path)
    fresh_sha256 = _verify_seal(
        fresh,
        "artifact_content_sha256",
        "phase2a_48_owner_proposal_fresh_seal_invalid",
    )
    fresh_items = fresh.get("items")
    if (
        fresh.get("schema") != FRESH_SCHEMA
        or fresh.get("source_owner_review_batch_content_sha256") != span_batch_sha256
        or not isinstance(fresh_items, list)
        or len(fresh_items) != EXPECTED_ITEM_COUNT
        or fresh.get("issue_technical_qualification_count") != 0
        or fresh.get("phase2b_authorized") is not False
        or fresh.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_48_owner_proposal_fresh_boundary_invalid")
    fresh_by_row = {str(item.get("row_id") or ""): item for item in fresh_items}

    snapshot = _load_json(snapshot_path)
    snapshot_sha256 = _verify_seal(
        snapshot,
        "snapshot_sha256",
        "phase2a_48_owner_proposal_snapshot_seal_invalid",
    )
    if snapshot.get("schema") != SNAPSHOT_SCHEMA or snapshot.get("issue_count") != 585:
        raise ValueError("phase2a_48_owner_proposal_snapshot_invalid")
    canonical_by_row = {
        str(issue.get("row_id") or ""): issue
        for case in snapshot.get("cases", [])
        for issue in case.get("issues", [])
    }

    proposed: list[dict[str, Any]] = []
    for span_item in span_items:
        row_id = str(span_item.get("row_id") or "")
        historical_record = historical_by_row.get(row_id)
        fresh_item = fresh_by_row.get(row_id)
        canonical = canonical_by_row.get(row_id)
        if historical_record is None or fresh_item is None or canonical is None:
            raise ValueError("phase2a_48_owner_proposal_row_binding_missing")
        if (
            fresh_item.get("all_candidate_components_match_fresh_official_anchors") is not True
            or fresh_item.get("semantic_proposition_binding_verified") is not False
            or fresh_item.get("owner_decision_required") is not True
            or span_item.get("semantic_proposition_binding_verified") is not False
        ):
            raise ValueError("phase2a_48_owner_proposal_row_not_ready_for_owner_review")
        spans = [
            {
                "chunk_id": span.get("chunk_id"),
                "source_version_id": span.get("source_version_id"),
                "content_sha256": span.get("content_sha256"),
                "title": span.get("title"),
                "canonical_url": span.get("canonical_url"),
                "canonical_citation": span.get("canonical_citation"),
                "locator": span.get("locator"),
                "text": span.get("text"),
                "as_of_date": span.get("as_of_date"),
            }
            for span in span_item.get("candidate_spans", [])
        ]
        material = {
            "schema": "legalbot.v111.phase2a.internal-proposition-span-owner-decision.v1",
            "status": "PROPOSED_NOT_OWNER_APPROVED",
            "row_id": row_id,
            "canonical_issue_id": canonical.get("issue_id"),
            "canonical_issue_label_sha256": canonical.get("issue_label_sha256"),
            "owner_typed_name": owner_typed_name.strip(),
            "owner_decision_date": owner_decision_date,
            "proposed_owner_outcome": "APPROVE_INTERNAL_PROPOSITION_AND_EXACT_SPAN_BINDING",
            "internal_research_tool_only": True,
            "professional_legal_certification": False,
            "legal_advice": False,
            "review_question": historical_record.get("question"),
            "proposed_exact_proposition_text": historical_record.get("operative_text"),
            "official_source_title": historical_record.get("source_title"),
            "official_source_type": historical_record.get("source_type"),
            "official_citation": historical_record.get("citation"),
            "official_legal_locator": historical_record.get("legal_locator"),
            "official_source_url": historical_record.get("official_source_url"),
            "exact_candidate_span_bindings": spans,
            "fresh_official_span_verification_record_content_sha256": fresh_item.get(
                "record_content_sha256"
            ),
            "all_candidate_components_match_fresh_2026_08_14_official_anchors": True,
            "proposed_determinations_if_approved": {
                "exact_proposition_is_material_to_this_internal_issue": True,
                "exact_candidate_spans_bind_the_proposition": True,
                "candidate_contains_the_exact_official_proposition_text": True,
                "new_candidate_source_not_required_for_this_exact_proposition": True,
                "gold_successor_binding_may_be_prepared": True,
            },
            "expressly_not_decided_or_authorized": {
                "automatic_source_admission_indexing_or_embedding": True,
                "whole_document_byte_mismatch_materiality_outside_exact_spans": True,
                "other_issues_or_propositions": True,
                "common_currentness_cutoff": True,
                "candidate_mutation_or_successor_build": True,
                "phase2b": True,
                "development30": True,
                "validation_promotion_or_live": True,
            },
            "decision_basis_sha256s": [
                span_item.get("record_content_sha256"),
                fresh_item.get("record_content_sha256"),
                _sealed(historical_record),
            ],
        }
        proposed.append({**material, "decision_content_sha256": _sealed(material)})

    if len(proposed) != EXPECTED_ITEM_COUNT or len({item["row_id"] for item in proposed}) != 48:
        raise ValueError("phase2a_48_owner_proposal_inventory_invalid")
    proposal_material = {
        "schema": "legalbot.v111.phase2a.internal-proposition-span-owner-proposal.v1",
        "status": "PROPOSED_NOT_OWNER_APPROVED",
        "authoritative": False,
        "owner_typed_name": owner_typed_name.strip(),
        "owner_decision_date": owner_decision_date,
        "item_count": len(proposed),
        "source_historical_staging_file_sha256": _sha256_file(historical_path),
        "historical_staging_hash_authoritative": False,
        "source_span_owner_review_batch_content_sha256": span_batch_sha256,
        "source_fresh_official_verification_content_sha256": fresh_sha256,
        "source_canonical_registry_snapshot_content_sha256": snapshot_sha256,
        "proposed_decisions": proposed,
        "authority_if_explicitly_approved": {
            "approve_exact_internal_proposition_and_span_bindings_for_48_rows": True,
            "prepare_versioned_gold_successor_bindings_for_48_rows": True,
            "continue_phase2a_remediation": True,
            "source_admission_indexing_or_embedding": False,
            "candidate_mutation_or_successor_build": False,
            "common_currentness_cutoff": False,
            "phase2b": False,
            "development30": False,
            "validation_promotion_or_live": False,
        },
    }
    proposal = {**proposal_material, "proposal_content_sha256": _sealed(proposal_material)}
    proposal_path = output_root / "PROPOSED-OWNER-DECISIONS-48.json"
    _write_exclusive(proposal_path, _pretty_json(proposal))

    approval_material = {
        "schema": "legalbot.v111.phase2a.internal-proposition-span-approval-request.v1",
        "status": "AWAITING_EXPLICIT_OWNER_REPLY",
        "owner_typed_name": owner_typed_name.strip(),
        "owner_decision_date": owner_decision_date,
        "proposal_content_sha256": proposal["proposal_content_sha256"],
        "proposal_file_sha256": _sha256_file(proposal_path),
        "item_count": len(proposed),
        "requested_reply": "OK",
        "approval_statement": (
            "I approve the exact 48 internal-tool proposition and span decisions bound to this "
            "payload. I authorize continued Phase-2A remediation only. I do not authorize source "
            "admission, candidate mutation, Phase 2B, Development 30, validation, promotion or live."
        ),
    }
    approval = {
        **approval_material,
        "approval_payload_content_sha256": _sealed(approval_material),
    }
    _write_exclusive(output_root / "APPROVAL-PAYLOAD.json", _pretty_json(approval))
    summary = (
        "OWNER ACTION: review PROPOSED-OWNER-DECISIONS-48.json. Reply exactly OK to approve "
        "only those 48 internal proposition/span bindings and continued Phase 2A. Phase 2B and "
        "Development 30 remain unauthorized.\n"
    )
    _write_exclusive(output_root / "OWNER-ACTION.txt", summary.encode())
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "item_count": len(proposed),
        "proposal_content_sha256": proposal["proposal_content_sha256"],
        "approval_payload_content_sha256": approval["approval_payload_content_sha256"],
        "requested_reply": "OK",
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.internal-proposition-owner-proposal-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except Exception:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--historical-review", required=True, type=Path)
    parser.add_argument("--span-owner-review-batch", required=True, type=Path)
    parser.add_argument("--fresh-official-verification", required=True, type=Path)
    parser.add_argument("--canonical-snapshot", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--owner-typed-name", required=True)
    parser.add_argument("--owner-decision-date", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = build_proposal(
            historical_path=args.historical_review.resolve(strict=True),
            span_batch_path=args.span_owner_review_batch.resolve(strict=True),
            fresh_verification_path=args.fresh_official_verification.resolve(strict=True),
            snapshot_path=args.canonical_snapshot.resolve(strict=True),
            output_root=args.output_root.resolve(),
            owner_typed_name=str(args.owner_typed_name),
            owner_decision_date=str(args.owner_decision_date),
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
