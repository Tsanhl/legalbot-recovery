#!/usr/bin/env python3
"""Apply an exact owner ``OK`` to the sealed 35-row rebinding proposal.

This create-only command records proposition-level materiality, source-admission
scope, and candidate-rebinding scope approved for the private internal research
tool.  It does not index or embed sources, build or mutate a candidate, qualify
an issue, authorize Phase 2B or Development 30, promote, validate, or activate
live use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROPOSAL_SCHEMA = "legalbot.v111.phase2a.rebinding-owner-proposal.v1"
APPROVAL_SCHEMA = "legalbot.v111.phase2a.rebinding-owner-approval-request.v1"
DECISION_SCHEMA = "legalbot.v111.phase2a.rebinding-owner-decision.v1"
EXPECTED_ITEM_COUNT = 35
EXPECTED_SOURCE_ADMISSION_COUNT = 23
EXPECTED_CANDIDATE_REBIND_COUNT = 12
EXPECTED_OWNER_LOCATOR_CONFIRMATION_COUNT = 3
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
        raise ValueError("phase2a_35_owner_approval_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_35_owner_approval_input_must_be_object")
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
        "phase2a_35_owner_approval_decision_seal_invalid",
    )
    action = value.get("required_candidate_action")
    source_admission = value.get("source_admission_if_approved")
    if (
        value.get("schema") != DECISION_SCHEMA
        or value.get("status") != "PROPOSED_NOT_OWNER_APPROVED"
        or value.get("proposed_owner_outcome")
        != "APPROVE_INTERNAL_PROPOSITION_MATERIALITY_AND_REBINDING_SCOPE"
        or value.get("internal_research_tool_only") is not True
        or value.get("professional_legal_certification") is not False
        or value.get("legal_advice") is not False
        or value.get("fresh_official_verification_status")
        not in {
            "EXACT_OFFICIAL_TEXT_AND_STATED_LOCATOR_MATCH",
            "EXACT_OFFICIAL_TEXT_DIFFERENT_OR_UNCONFIRMED_LOCATOR",
        }
        or value.get("owner_locator_confirmation_required")
        is not (
            value.get("fresh_official_verification_status")
            == "EXACT_OFFICIAL_TEXT_DIFFERENT_OR_UNCONFIRMED_LOCATOR"
        )
        or action
        not in {
            "OWNER_SOURCE_ADMISSION_DECISION_REQUIRED",
            "CANDIDATE_REBIND_OR_SUCCESSOR_DECISION_REQUIRED",
        }
        or source_admission is not (action == "OWNER_SOURCE_ADMISSION_DECISION_REQUIRED")
        or value.get("candidate_rebind_or_successor_scope_if_approved") is not True
        or value.get("defer_candidate_build_until_one_consolidated_phase2a_scope") is not True
        or value.get("expressly_not_authorized")
        != {
            "automatic_indexing_or_embedding": True,
            "candidate_build_before_full_consolidated_scope": True,
            "common_currentness_cutoff": True,
            "development30": True,
            "phase2b": True,
            "validation_promotion_or_live": True,
        }
    ):
        raise ValueError("phase2a_35_owner_approval_decision_boundary_invalid")
    return decision_sha256


def apply_approval(
    *,
    proposal_path: Path,
    approval_path: Path,
    output_root: Path,
    owner_reply: str,
    recorded_at: datetime,
) -> dict[str, Any]:
    """Record and apply the exact 35-row approval without advancing a phase gate."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_35_owner_approval_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_35_owner_approval_output_mode_invalid")
    if recorded_at.tzinfo is None:
        raise ValueError("phase2a_35_owner_approval_recorded_at_naive")

    proposal = _load_json(proposal_path)
    approval = _load_json(approval_path)
    proposal_sha256 = _verify_seal(
        proposal,
        "proposal_content_sha256",
        "phase2a_35_owner_approval_proposal_seal_invalid",
    )
    approval_sha256 = _verify_seal(
        approval,
        "approval_payload_content_sha256",
        "phase2a_35_owner_approval_payload_seal_invalid",
    )
    authority = proposal.get("authority_if_explicitly_approved")
    if (
        proposal.get("schema") != PROPOSAL_SCHEMA
        or proposal.get("status") != "PROPOSED_NOT_OWNER_APPROVED"
        or proposal.get("authoritative") is not False
        or proposal.get("item_count") != EXPECTED_ITEM_COUNT
        or proposal.get("source_admission_row_count") != EXPECTED_SOURCE_ADMISSION_COUNT
        or proposal.get("candidate_rebind_row_count") != EXPECTED_CANDIDATE_REBIND_COUNT
        or proposal.get("owner_locator_confirmation_count")
        != EXPECTED_OWNER_LOCATOR_CONFIRMATION_COUNT
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
            "approve_internal_proposition_materiality_for_35_rows": True,
            "confirm_three_stated_locators_as_owner_decisions": True,
            "authorize_source_admission_scope_for_23_rows": True,
            "authorize_candidate_rebind_or_successor_scope_for_35_rows": True,
            "defer_build_until_one_consolidated_phase2a_scope": True,
            "continue_phase2a_remediation": True,
            "automatic_indexing_or_embedding": False,
            "candidate_build_now": False,
            "common_currentness_cutoff": False,
            "development30": False,
            "phase2b": False,
            "validation_promotion_or_live": False,
        }
    ):
        raise ValueError("phase2a_35_owner_approval_authority_boundary_invalid")

    decisions = proposal.get("proposed_decisions")
    if not isinstance(decisions, list) or len(decisions) != EXPECTED_ITEM_COUNT:
        raise ValueError("phase2a_35_owner_approval_decision_inventory_invalid")

    approved_decisions: list[dict[str, Any]] = []
    source_admission_scope: list[dict[str, Any]] = []
    candidate_rebinding_scope: list[dict[str, Any]] = []
    seen_rows: set[str] = set()
    actions: Counter[str] = Counter()
    locator_confirmations = 0
    for proposed in decisions:
        if not isinstance(proposed, dict):
            raise ValueError("phase2a_35_owner_approval_decision_invalid")
        decision_sha256 = _validate_decision(proposed)
        row_id = str(proposed.get("row_id") or "")
        if not row_id or row_id in seen_rows:
            raise ValueError("phase2a_35_owner_approval_duplicate_row")
        seen_rows.add(row_id)
        action = str(proposed["required_candidate_action"])
        actions[action] += 1
        locator_confirmations += int(proposed["owner_locator_confirmation_required"] is True)

        approved_material = {
            "schema": "legalbot.v111.phase2a.rebinding-owner-approved.v1",
            "status": "OWNER_APPROVED_INTERNAL_RESEARCH_TOOL_SCOPE",
            "row_id": row_id,
            "owner_typed_name": proposal["owner_typed_name"],
            "owner_decision_date": proposal["owner_decision_date"],
            "source_proposed_decision_content_sha256": decision_sha256,
            "owner_outcome": proposed["proposed_owner_outcome"],
            "internal_research_tool_only": True,
            "professional_legal_certification": False,
            "legal_advice": False,
            "exact_proposition_text": proposed["exact_proposition_text"],
            "official_source_title": proposed["official_source_title"],
            "official_source_type": proposed["official_source_type"],
            "official_citation": proposed["official_citation"],
            "official_legal_locator": proposed["official_legal_locator"],
            "official_source_url": proposed["official_source_url"],
            "fresh_official_verification_status": proposed["fresh_official_verification_status"],
            "owner_locator_confirmed": proposed["owner_locator_confirmation_required"],
            "source_verification_record_content_sha256": proposed[
                "source_verification_record_content_sha256"
            ],
            "required_candidate_action": action,
            "source_admission_scope_authorized": proposed["source_admission_if_approved"],
            "candidate_rebind_or_successor_scope_authorized": True,
            "automatic_indexing_or_embedding_authorized": False,
            "candidate_build_authorized": False,
            "common_currentness_cutoff_adopted": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        approved = {
            **approved_material,
            "approved_decision_content_sha256": _sealed(approved_material),
        }
        approved_decisions.append(approved)

        scope_material = {
            "row_id": row_id,
            "exact_proposition_text": proposed["exact_proposition_text"],
            "official_source_title": proposed["official_source_title"],
            "official_source_type": proposed["official_source_type"],
            "official_citation": proposed["official_citation"],
            "official_legal_locator": proposed["official_legal_locator"],
            "official_source_url": proposed["official_source_url"],
            "source_verification_record_content_sha256": proposed[
                "source_verification_record_content_sha256"
            ],
            "owner_approved_decision_content_sha256": approved["approved_decision_content_sha256"],
        }
        candidate_rebinding_scope.append(scope_material)
        if proposed["source_admission_if_approved"] is True:
            source_admission_scope.append(scope_material)

    if (
        actions
        != Counter(
            {
                "OWNER_SOURCE_ADMISSION_DECISION_REQUIRED": (EXPECTED_SOURCE_ADMISSION_COUNT),
                "CANDIDATE_REBIND_OR_SUCCESSOR_DECISION_REQUIRED": (
                    EXPECTED_CANDIDATE_REBIND_COUNT
                ),
            }
        )
        or locator_confirmations != EXPECTED_OWNER_LOCATOR_CONFIRMATION_COUNT
    ):
        raise ValueError("phase2a_35_owner_approval_count_invariant_failed")

    approved_decisions.sort(key=lambda item: str(item["row_id"]))
    source_admission_scope.sort(key=lambda item: str(item["row_id"]))
    candidate_rebinding_scope.sort(key=lambda item: str(item["row_id"]))

    receipt_material = {
        "schema": "legalbot.v111.phase2a.rebinding-owner-receipt.v1",
        "status": "OWNER_APPROVED_35_REBINDING_SCOPES_PHASE2A_ONLY",
        "owner_typed_name": proposal["owner_typed_name"],
        "owner_decision_date": proposal["owner_decision_date"],
        "owner_reply": owner_reply,
        "recorded_at": recorded_at.astimezone(UTC).isoformat(timespec="seconds"),
        "approval_payload_content_sha256": approval_sha256,
        "approval_payload_file_sha256": _sha256_file(approval_path),
        "proposal_content_sha256": proposal_sha256,
        "proposal_file_sha256": _sha256_file(proposal_path),
        "approved_item_count": len(approved_decisions),
        "approved_source_admission_scope_count": len(source_admission_scope),
        "approved_candidate_rebinding_scope_count": len(candidate_rebinding_scope),
        "continued_phase2a_remediation_authorized": True,
        "automatic_indexing_or_embedding_authorized": False,
        "candidate_build_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation_promotion_or_live_authorized": False,
    }
    receipt = {**receipt_material, "receipt_content_sha256": _sealed(receipt_material)}

    package_material = {
        "schema": "legalbot.v111.phase2a.rebinding-owner-approved-package.v1",
        "status": "OWNER_APPROVED_PHASE2A_REBINDING_SCOPES",
        "owner_approval_receipt_content_sha256": receipt["receipt_content_sha256"],
        "item_count": len(approved_decisions),
        "decisions": approved_decisions,
        "automatic_indexing_or_embedding_authorized": False,
        "candidate_build_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    package = {
        **package_material,
        "approved_package_content_sha256": _sealed(package_material),
    }

    source_material = {
        "schema": "legalbot.v111.phase2a.source-admission-scope.v1",
        "status": "OWNER_APPROVED_SCOPE_AWAITING_CONSOLIDATED_ADMISSION_MANIFEST",
        "source_owner_approved_package_content_sha256": package["approved_package_content_sha256"],
        "row_count": len(source_admission_scope),
        "rows": source_admission_scope,
        "automatic_indexing_or_embedding_authorized": False,
        "candidate_build_authorized": False,
    }
    source_artifact = {
        **source_material,
        "artifact_content_sha256": _sealed(source_material),
    }

    rebind_material = {
        "schema": "legalbot.v111.phase2a.candidate-rebinding-scope.v1",
        "status": "OWNER_APPROVED_SCOPE_AWAITING_ONE_CONSOLIDATED_CANDIDATE_DECISION",
        "source_owner_approved_package_content_sha256": package["approved_package_content_sha256"],
        "row_count": len(candidate_rebinding_scope),
        "rows": candidate_rebinding_scope,
        "sealed_predecessor_mutated": False,
        "candidate_build_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    rebind_artifact = {
        **rebind_material,
        "artifact_content_sha256": _sealed(rebind_material),
    }

    progress_material = {
        "schema": "legalbot.v111.phase2a.progress-after-83-owner-decisions.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES",
        "canonical_issue_count": 585,
        "previous_owner_adopted_internal_binding_count": 48,
        "new_owner_approved_materiality_scope_count": 35,
        "recorded_owner_decision_count": 83,
        "remaining_owner_decision_issue_count": 502,
        "technically_evidence_ready_owner_adopted_count": 48,
        "rebinding_or_successor_work_pending_count": 35,
        "all585_technical_qualification_passed": False,
        "common_currentness_cutoff_supportable": False,
        "automatic_indexing_or_embedding_authorized": False,
        "candidate_build_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "terminal_verdict": (
            "PHASE 2A REMEDIATION CONTINUES — 83 OWNER DECISIONS RECORDED; "
            "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
        ),
    }
    progress = {
        **progress_material,
        "progress_content_sha256": _sealed(progress_material),
    }

    artifacts = {
        "OWNER-APPROVAL-RECEIPT-35.json": receipt,
        "OWNER-DECISIONS-APPROVED-35.json": package,
        "SOURCE-ADMISSION-SCOPE-23.json": source_artifact,
        "CANDIDATE-REBINDING-SCOPE-35.json": rebind_artifact,
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
        "approved_package_content_sha256": package["approved_package_content_sha256"],
        "source_admission_scope_content_sha256": source_artifact["artifact_content_sha256"],
        "candidate_rebinding_scope_content_sha256": rebind_artifact["artifact_content_sha256"],
        "approved_item_count": EXPECTED_ITEM_COUNT,
        "recorded_owner_decision_count": 83,
        "remaining_owner_decision_issue_count": 502,
        "candidate_build_authorized": False,
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
            "schema": "legalbot.v111.phase2a.rebinding-owner-approval-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "candidate_build_authorized": False,
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
