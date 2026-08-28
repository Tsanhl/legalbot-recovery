#!/usr/bin/env python3
"""Build one sealed owner proposal for 35 fresh-official rebinding rows.

The proposal may authorize proposition-level materiality, source admission
scope, and later inclusion in one consolidated successor candidate.  It does
not apply any decision, build a candidate, qualify an issue, or authorize
Phase 2B or Development 30.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

VERIFICATION_SCHEMA = "legalbot.v111.phase2a.official-rebinding-verification.v1"
QUEUE_SCHEMA = "legalbot.v111.phase2a.official-rebinding-queue.v1"
EXPECTED_EXACT_COUNT = 35
EXPECTED_CONFIRMED_LOCATOR_COUNT = 32
EXPECTED_LOCATOR_CONFIRMATION_COUNT = 3
EXPECTED_SOURCE_ADMISSION_ROW_COUNT = 23
EXPECTED_REBIND_ROW_COUNT = 12
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


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_35_rebinding_proposal_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_35_rebinding_proposal_input_must_be_object")
    return value


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
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
    verification_path: Path,
    queue_path: Path,
    output_root: Path,
    owner_name: str,
    owner_decision_date: str,
) -> dict[str, Any]:
    """Prepare but do not apply the exact 35-row owner decision."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_35_rebinding_proposal_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_35_rebinding_proposal_output_mode_invalid")
    if not owner_name.strip() or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", owner_decision_date):
        raise ValueError("phase2a_35_rebinding_proposal_owner_identity_invalid")

    verification = _load_object(verification_path)
    queue = _load_object(queue_path)
    verification_sha256 = _verify_seal(
        verification,
        "artifact_content_sha256",
        "phase2a_35_rebinding_proposal_verification_seal_invalid",
    )
    queue_sha256 = _verify_seal(
        queue,
        "artifact_content_sha256",
        "phase2a_35_rebinding_proposal_queue_seal_invalid",
    )
    if (
        verification.get("schema") != VERIFICATION_SCHEMA
        or verification.get("record_count") != 89
        or verification.get("exact_official_text_count") != EXPECTED_EXACT_COUNT
        or verification.get("correction_required_count") != 54
        or verification.get("source_queue_content_sha256") != queue_sha256
        or verification.get("issue_technical_qualification_count") != 0
        or verification.get("phase2b_authorized") is not False
        or queue.get("schema") != QUEUE_SCHEMA
        or queue.get("item_count") != 89
        or queue.get("automatic_source_admission") is not False
        or queue.get("phase2b_authorized") is not False
    ):
        raise ValueError("phase2a_35_rebinding_proposal_boundary_invalid")
    queue_by_row = {str(item.get("row_id") or ""): item for item in queue.get("items", [])}
    if len(queue_by_row) != 89:
        raise ValueError("phase2a_35_rebinding_proposal_queue_duplicate")

    decisions: list[dict[str, Any]] = []
    locator_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    for record in verification.get("records", []):
        _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_35_rebinding_proposal_record_seal_invalid",
        )
        if record.get("all_components_exact_in_fresh_official_bytes") is not True:
            continue
        row_id = str(record.get("row_id") or "")
        queue_item = queue_by_row.get(row_id)
        if queue_item is None:
            raise ValueError("phase2a_35_rebinding_proposal_row_missing")
        locator_status = str(record.get("verification_status") or "")
        action = str(record.get("required_candidate_action") or "")
        if locator_status not in {
            "EXACT_OFFICIAL_TEXT_AND_STATED_LOCATOR_MATCH",
            "EXACT_OFFICIAL_TEXT_DIFFERENT_OR_UNCONFIRMED_LOCATOR",
        } or action not in {
            "OWNER_SOURCE_ADMISSION_DECISION_REQUIRED",
            "CANDIDATE_REBIND_OR_SUCCESSOR_DECISION_REQUIRED",
        }:
            raise ValueError("phase2a_35_rebinding_proposal_record_status_invalid")
        material = {
            "schema": "legalbot.v111.phase2a.rebinding-owner-decision.v1",
            "status": "PROPOSED_NOT_OWNER_APPROVED",
            "row_id": row_id,
            "owner_typed_name": owner_name.strip(),
            "owner_decision_date": owner_decision_date,
            "proposed_owner_outcome": (
                "APPROVE_INTERNAL_PROPOSITION_MATERIALITY_AND_REBINDING_SCOPE"
            ),
            "internal_research_tool_only": True,
            "professional_legal_certification": False,
            "legal_advice": False,
            "exact_proposition_text": record.get("proposed_exact_proposition_text"),
            "official_source_title": record.get("official_source_title"),
            "official_source_type": queue_item.get("official_source_type"),
            "official_citation": record.get("official_citation"),
            "official_legal_locator": record.get("stated_official_legal_locator"),
            "official_source_url": queue_item.get("official_source_url"),
            "fresh_official_verification_status": locator_status,
            "owner_locator_confirmation_required": (
                locator_status == "EXACT_OFFICIAL_TEXT_DIFFERENT_OR_UNCONFIRMED_LOCATOR"
            ),
            "source_verification_record_content_sha256": record.get("record_content_sha256"),
            "required_candidate_action": action,
            "source_admission_if_approved": (action == "OWNER_SOURCE_ADMISSION_DECISION_REQUIRED"),
            "candidate_rebind_or_successor_scope_if_approved": True,
            "defer_candidate_build_until_one_consolidated_phase2a_scope": True,
            "expressly_not_authorized": {
                "automatic_indexing_or_embedding": True,
                "candidate_build_before_full_consolidated_scope": True,
                "common_currentness_cutoff": True,
                "development30": True,
                "phase2b": True,
                "validation_promotion_or_live": True,
            },
        }
        decisions.append({**material, "decision_content_sha256": _sealed(material)})
        locator_counts[locator_status] += 1
        action_counts[action] += 1

    decisions.sort(key=lambda item: str(item["row_id"]))
    if (
        len(decisions) != EXPECTED_EXACT_COUNT
        or locator_counts
        != Counter(
            {
                "EXACT_OFFICIAL_TEXT_AND_STATED_LOCATOR_MATCH": (EXPECTED_CONFIRMED_LOCATOR_COUNT),
                "EXACT_OFFICIAL_TEXT_DIFFERENT_OR_UNCONFIRMED_LOCATOR": (
                    EXPECTED_LOCATOR_CONFIRMATION_COUNT
                ),
            }
        )
        or action_counts
        != Counter(
            {
                "OWNER_SOURCE_ADMISSION_DECISION_REQUIRED": (EXPECTED_SOURCE_ADMISSION_ROW_COUNT),
                "CANDIDATE_REBIND_OR_SUCCESSOR_DECISION_REQUIRED": (EXPECTED_REBIND_ROW_COUNT),
            }
        )
    ):
        raise ValueError("phase2a_35_rebinding_proposal_count_invariant_failed")

    proposal_material = {
        "schema": "legalbot.v111.phase2a.rebinding-owner-proposal.v1",
        "status": "PROPOSED_NOT_OWNER_APPROVED",
        "authoritative": False,
        "owner_typed_name": owner_name.strip(),
        "owner_decision_date": owner_decision_date,
        "source_verification_content_sha256": verification_sha256,
        "source_verification_file_sha256": _sha256_file(verification_path),
        "source_queue_content_sha256": queue_sha256,
        "item_count": len(decisions),
        "confirmed_locator_count": EXPECTED_CONFIRMED_LOCATOR_COUNT,
        "owner_locator_confirmation_count": EXPECTED_LOCATOR_CONFIRMATION_COUNT,
        "source_admission_row_count": EXPECTED_SOURCE_ADMISSION_ROW_COUNT,
        "candidate_rebind_row_count": EXPECTED_REBIND_ROW_COUNT,
        "proposed_decisions": decisions,
        "authority_if_explicitly_approved": {
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
        },
    }
    proposal = {
        **proposal_material,
        "proposal_content_sha256": _sealed(proposal_material),
    }
    proposal_path = output_root / "PROPOSED-OWNER-DECISIONS-35.json"
    _write_exclusive(proposal_path, _pretty_json(proposal))
    approval_material = {
        "schema": "legalbot.v111.phase2a.rebinding-owner-approval-request.v1",
        "status": "AWAITING_EXPLICIT_OWNER_REPLY",
        "owner_typed_name": owner_name.strip(),
        "owner_decision_date": owner_decision_date,
        "proposal_content_sha256": proposal["proposal_content_sha256"],
        "proposal_file_sha256": _sha256_file(proposal_path),
        "item_count": EXPECTED_EXACT_COUNT,
        "approval_statement": (
            "I approve the exact 35 internal-tool proposition materiality decisions and "
            "rebinding scopes bound to this payload, including explicit confirmation of "
            "the three stated locators marked for owner confirmation. I authorize "
            "proposition-level source-admission scope for 23 rows and candidate rebinding "
            "scope for all 35, but require any candidate build to wait for one consolidated "
            "Phase-2A scope. I authorize continued Phase-2A remediation only. I do not "
            "authorize Phase 2B, Development 30, validation, promotion or live."
        ),
        "requested_reply": "OK",
    }
    approval = {
        **approval_material,
        "approval_payload_content_sha256": _sealed(approval_material),
    }
    _write_exclusive(output_root / "APPROVAL-PAYLOAD.json", _pretty_json(approval))
    _write_exclusive(
        output_root / "OWNER-ACTION.txt",
        b"Review PROPOSED-OWNER-DECISIONS-35.json and APPROVAL-PAYLOAD.json. "
        b"Reply exactly OK to approve only that sealed Phase-2A scope. Phase 2B and "
        b"Development 30 remain unauthorized.\n",
    )
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in files).encode(),
    )
    return {
        "output_root": str(output_root),
        "proposal_content_sha256": proposal["proposal_content_sha256"],
        "approval_payload_content_sha256": approval["approval_payload_content_sha256"],
        "item_count": EXPECTED_EXACT_COUNT,
        "source_admission_row_count": EXPECTED_SOURCE_ADMISSION_ROW_COUNT,
        "candidate_rebind_row_count": EXPECTED_REBIND_ROW_COUNT,
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
            "schema": "legalbot.v111.phase2a.rebinding-owner-proposal-failure.v1",
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
    parser.add_argument("--verification", required=True, type=Path)
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--owner-name", required=True)
    parser.add_argument("--owner-decision-date", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = build_proposal(
            verification_path=args.verification.resolve(strict=True),
            queue_path=args.queue.resolve(strict=True),
            output_root=args.output_root.resolve(),
            owner_name=str(args.owner_name),
            owner_decision_date=str(args.owner_decision_date),
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
