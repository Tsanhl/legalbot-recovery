#!/usr/bin/env python3
"""Apply an exact owner ``OK`` to the sealed 48-row Phase-2A proposal.

This create-only command records the owner receipt, emits approved internal
proposition/span bindings, and prepares a versioned gold-successor binding
artifact.  It cannot admit sources, mutate the candidate, authorize Phase 2B,
authorize Development 30, promote, validate, or activate live use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROPOSAL_SCHEMA = "legalbot.v111.phase2a.internal-proposition-span-owner-proposal.v1"
APPROVAL_SCHEMA = "legalbot.v111.phase2a.internal-proposition-span-approval-request.v1"
DECISION_SCHEMA = "legalbot.v111.phase2a.internal-proposition-span-owner-decision.v1"
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
        raise ValueError("phase2a_48_owner_approval_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_48_owner_approval_input_must_be_object")
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


def _validate_decision(value: dict[str, Any]) -> str:
    decision_sha256 = _verify_seal(
        value,
        "decision_content_sha256",
        "phase2a_48_owner_approval_decision_seal_invalid",
    )
    forbidden = value.get("expressly_not_decided_or_authorized")
    if (
        value.get("schema") != DECISION_SCHEMA
        or value.get("status") != "PROPOSED_NOT_OWNER_APPROVED"
        or value.get("proposed_owner_outcome")
        != "APPROVE_INTERNAL_PROPOSITION_AND_EXACT_SPAN_BINDING"
        or value.get("internal_research_tool_only") is not True
        or value.get("professional_legal_certification") is not False
        or value.get("legal_advice") is not False
        or not isinstance(value.get("exact_candidate_span_bindings"), list)
        or not value["exact_candidate_span_bindings"]
        or value.get("all_candidate_components_match_fresh_2026_08_14_official_anchors") is not True
        or forbidden
        != {
            "automatic_source_admission_indexing_or_embedding": True,
            "candidate_mutation_or_successor_build": True,
            "common_currentness_cutoff": True,
            "development30": True,
            "other_issues_or_propositions": True,
            "phase2b": True,
            "validation_promotion_or_live": True,
            "whole_document_byte_mismatch_materiality_outside_exact_spans": True,
        }
    ):
        raise ValueError("phase2a_48_owner_approval_decision_boundary_invalid")
    return decision_sha256


def apply_approval(
    *,
    proposal_path: Path,
    approval_path: Path,
    output_root: Path,
    owner_reply: str,
    recorded_at: datetime,
) -> dict[str, Any]:
    """Record and apply the exact 48-row approval without advancing a phase gate."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_48_owner_approval_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_48_owner_approval_output_mode_invalid")
    if recorded_at.tzinfo is None:
        raise ValueError("phase2a_48_owner_approval_recorded_at_naive")

    proposal = _load_json(proposal_path)
    approval = _load_json(approval_path)
    proposal_sha256 = _verify_seal(
        proposal,
        "proposal_content_sha256",
        "phase2a_48_owner_approval_proposal_seal_invalid",
    )
    approval_sha256 = _verify_seal(
        approval,
        "approval_payload_content_sha256",
        "phase2a_48_owner_approval_payload_seal_invalid",
    )
    authority = proposal.get("authority_if_explicitly_approved")
    if (
        proposal.get("schema") != PROPOSAL_SCHEMA
        or proposal.get("status") != "PROPOSED_NOT_OWNER_APPROVED"
        or proposal.get("authoritative") is not False
        or proposal.get("item_count") != EXPECTED_ITEM_COUNT
        or approval.get("schema") != APPROVAL_SCHEMA
        or approval.get("status") != "AWAITING_EXPLICIT_OWNER_REPLY"
        or approval.get("proposal_content_sha256") != proposal_sha256
        or approval.get("proposal_file_sha256") != _sha256_file(proposal_path)
        or approval.get("item_count") != EXPECTED_ITEM_COUNT
        or approval.get("owner_typed_name") != proposal.get("owner_typed_name")
        or approval.get("owner_decision_date") != proposal.get("owner_decision_date")
        or approval.get("requested_reply") != "OK"
        or owner_reply != "OK"
        or authority
        != {
            "approve_exact_internal_proposition_and_span_bindings_for_48_rows": True,
            "candidate_mutation_or_successor_build": False,
            "common_currentness_cutoff": False,
            "continue_phase2a_remediation": True,
            "development30": False,
            "phase2b": False,
            "prepare_versioned_gold_successor_bindings_for_48_rows": True,
            "source_admission_indexing_or_embedding": False,
            "validation_promotion_or_live": False,
        }
    ):
        raise ValueError("phase2a_48_owner_approval_authority_boundary_invalid")

    decisions = proposal.get("proposed_decisions")
    if not isinstance(decisions, list) or len(decisions) != EXPECTED_ITEM_COUNT:
        raise ValueError("phase2a_48_owner_approval_decision_inventory_invalid")
    approved_decisions: list[dict[str, Any]] = []
    gold_bindings: list[dict[str, Any]] = []
    seen_rows: set[str] = set()
    for proposed in decisions:
        if not isinstance(proposed, dict):
            raise ValueError("phase2a_48_owner_approval_decision_invalid")
        decision_sha256 = _validate_decision(proposed)
        row_id = str(proposed.get("row_id") or "")
        if not row_id or row_id in seen_rows:
            raise ValueError("phase2a_48_owner_approval_duplicate_row")
        seen_rows.add(row_id)
        approved_material = {
            "schema": "legalbot.v111.phase2a.internal-proposition-span-owner-approved.v1",
            "status": "OWNER_APPROVED_INTERNAL_RESEARCH_TOOL_BINDING",
            "row_id": row_id,
            "owner_typed_name": proposal["owner_typed_name"],
            "owner_decision_date": proposal["owner_decision_date"],
            "source_proposed_decision_content_sha256": decision_sha256,
            "owner_outcome": proposed["proposed_owner_outcome"],
            "internal_research_tool_only": True,
            "professional_legal_certification": False,
            "legal_advice": False,
            "exact_proposition_text": proposed["proposed_exact_proposition_text"],
            "official_source_title": proposed["official_source_title"],
            "official_source_type": proposed["official_source_type"],
            "official_citation": proposed["official_citation"],
            "official_legal_locator": proposed["official_legal_locator"],
            "official_source_url": proposed["official_source_url"],
            "exact_candidate_span_bindings": proposed["exact_candidate_span_bindings"],
            "fresh_official_span_verification_record_content_sha256": proposed[
                "fresh_official_span_verification_record_content_sha256"
            ],
            "approved_determinations": proposed["proposed_determinations_if_approved"],
            "not_decided_or_authorized": proposed["expressly_not_decided_or_authorized"],
            "source_admission_authorized": False,
            "candidate_mutation_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        approved = {
            **approved_material,
            "approved_decision_content_sha256": _sealed(approved_material),
        }
        approved_decisions.append(approved)
        binding_material = {
            "schema": "legalbot.v111.phase2a.gold-successor-binding.v1",
            "row_id": row_id,
            "canonical_issue_id": proposed["canonical_issue_id"],
            "canonical_issue_label_sha256": proposed["canonical_issue_label_sha256"],
            "exact_proposition_text": proposed["proposed_exact_proposition_text"],
            "official_source_title": proposed["official_source_title"],
            "official_source_type": proposed["official_source_type"],
            "official_citation": proposed["official_citation"],
            "official_legal_locator": proposed["official_legal_locator"],
            "official_source_url": proposed["official_source_url"],
            "exact_span_bindings": proposed["exact_candidate_span_bindings"],
            "owner_approved_decision_content_sha256": approved["approved_decision_content_sha256"],
            "technical_status": "TECHNICALLY_EVIDENCE_READY_OWNER_ADOPTED_INTERNAL",
            "candidate_change_required_for_exact_proposition": False,
            "whole_document_byte_mismatch_outside_exact_spans_resolved": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
        }
        gold_bindings.append(
            {**binding_material, "binding_content_sha256": _sealed(binding_material)}
        )

    receipt_material = {
        "schema": "legalbot.v111.phase2a.internal-proposition-span-owner-receipt.v1",
        "status": "OWNER_APPROVED_48_INTERNAL_BINDINGS_PHASE2A_ONLY",
        "owner_typed_name": proposal["owner_typed_name"],
        "owner_decision_date": proposal["owner_decision_date"],
        "owner_reply": owner_reply,
        "recorded_at": recorded_at.astimezone(UTC).isoformat(timespec="seconds"),
        "approval_payload_content_sha256": approval_sha256,
        "approval_payload_file_sha256": _sha256_file(approval_path),
        "proposal_content_sha256": proposal_sha256,
        "proposal_file_sha256": _sha256_file(proposal_path),
        "approved_item_count": len(approved_decisions),
        "continued_phase2a_remediation_authorized": True,
        "source_admission_indexing_or_embedding_authorized": False,
        "candidate_mutation_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation_promotion_or_live_authorized": False,
    }
    receipt = {**receipt_material, "receipt_content_sha256": _sealed(receipt_material)}

    approved_material = {
        "schema": "legalbot.v111.phase2a.internal-proposition-span-approved-package.v1",
        "status": "OWNER_APPROVED_PHASE2A_INTERNAL_BINDINGS",
        "owner_approval_receipt_content_sha256": receipt["receipt_content_sha256"],
        "item_count": len(approved_decisions),
        "decisions": approved_decisions,
        "source_admission_authorized": False,
        "candidate_mutation_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    approved_package = {
        **approved_material,
        "approved_package_content_sha256": _sealed(approved_material),
    }
    gold_material = {
        "schema": "legalbot.v111.phase2a.gold-successor-bindings.v1",
        "status": "VERSIONED_SUCCESSOR_BINDINGS_PREPARED_NOT_CANONICAL_REGISTRY_MUTATION",
        "source_owner_approved_package_content_sha256": approved_package[
            "approved_package_content_sha256"
        ],
        "binding_count": len(gold_bindings),
        "bindings": gold_bindings,
        "original_registry_mutated": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    gold = {**gold_material, "artifact_content_sha256": _sealed(gold_material)}
    progress_material = {
        "schema": "legalbot.v111.phase2a.progress-after-48-owner-bindings.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES",
        "canonical_issue_count": 585,
        "owner_adopted_internal_binding_count": 48,
        "remaining_blocked_material_issue_count": 537,
        "all585_technical_qualification_passed": False,
        "common_currentness_cutoff_supportable": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "terminal_verdict": (
            "PHASE 2A REMEDIATION CONTINUES — 48 INTERNAL BINDINGS OWNER-ADOPTED; "
            "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
        ),
    }
    progress = {**progress_material, "progress_content_sha256": _sealed(progress_material)}

    artifacts = {
        "OWNER-APPROVAL-RECEIPT-48.json": receipt,
        "OWNER-DECISIONS-APPROVED-48.json": approved_package,
        "GOLD-SUCCESSOR-BINDINGS-48.json": gold,
        "PHASE2A-PROGRESS.json": progress,
    }
    for name, artifact in artifacts.items():
        _write_exclusive(output_root / name, _pretty_json(artifact))
    _write_exclusive(output_root / "OUTCOME.txt", (progress["terminal_verdict"] + "\n").encode())
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "receipt_content_sha256": receipt["receipt_content_sha256"],
        "approved_package_content_sha256": approved_package["approved_package_content_sha256"],
        "gold_successor_bindings_content_sha256": gold["artifact_content_sha256"],
        "approved_binding_count": 48,
        "remaining_blocked_material_issue_count": 537,
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
            "schema": "legalbot.v111.phase2a.internal-proposition-owner-approval-failure.v1",
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
    parser.add_argument("--proposal", required=True, type=Path)
    parser.add_argument("--approval-payload", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--owner-reply", required=True)
    parser.add_argument("--recorded-at", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        recorded_at = datetime.fromisoformat(str(args.recorded_at).replace("Z", "+00:00"))
        result = apply_approval(
            proposal_path=args.proposal.resolve(strict=True),
            approval_path=args.approval_payload.resolve(strict=True),
            output_root=args.output_root.resolve(),
            owner_reply=str(args.owner_reply),
            recorded_at=recorded_at,
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
