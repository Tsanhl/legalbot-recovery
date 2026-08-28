#!/usr/bin/env python3
"""Record an explicit owner reply against an exact Phase-2A decision proposal.

This command is create-only.  It validates every proposed item decision against
the sealed owner-review batches, writes an immutable typed owner receipt, and
emits the approved decision package.  It cannot authorize Phase 2B,
Development 30, source admission, indexing, embedding, promotion or live use.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts import build_v111_phase2a_owner_review as owner_review  # noqa: E402

PROPOSAL_SCHEMA = "legalbot.v111.phase2a.owner-decision-proposal.v1"
APPROVAL_REQUEST_SCHEMA = "legalbot.v111.phase2ab.owner-approval-request.v1"
RECEIPT_SCHEMA = "legalbot.v111.phase2a.owner-approval-receipt.v1"
APPROVED_PACKAGE_SCHEMA = "legalbot.v111.phase2a.owner-decisions-approved.v1"
EXPECTED_CATEGORY_COUNTS = {
    "issue": 585,
    "legislative_effect": 1896,
    "judgment": 20,
    "source_version": 68,
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_content_seal(payload: dict[str, Any], field: str) -> str:
    material = dict(payload)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or _sha256_bytes(_canonical_json(material)) != supplied:
        raise ValueError(f"phase2a_owner_approval_{field}_invalid")
    return supplied


def _write_exclusive(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)


def _load_source_items(source_review_root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    prefixes = {
        "issue": "issue",
        "legislative_effect": "legislative-effect",
        "judgment": "judgment",
        "source_version": "source-version",
    }
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for category, prefix in prefixes.items():
        for path in sorted(source_review_root.glob(f"{prefix}-batch-*.json")):
            batch = json.loads(path.read_bytes())
            for item in batch.get("items", []):
                key = (category, str(item.get("item_id") or ""))
                if key in result:
                    raise ValueError("phase2a_owner_approval_duplicate_source_item")
                result[key] = item
    counts = Counter(category for category, _ in result)
    if dict(counts) != EXPECTED_CATEGORY_COUNTS:
        raise ValueError("phase2a_owner_approval_source_inventory_invalid")
    return result


def apply_owner_approval(
    *,
    proposal_path: Path,
    approval_request_path: Path,
    source_review_root: Path,
    output_root: Path,
    owner_reply: str,
    recorded_at: datetime,
) -> dict[str, Any]:
    """Validate and record one exact owner reply without expanding its authority."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_owner_approval_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_owner_approval_output_mode_invalid")

    proposal = json.loads(proposal_path.read_bytes())
    approval = json.loads(approval_request_path.read_bytes())
    proposal_seal = _verify_content_seal(proposal, "proposal_content_sha256")
    approval_seal = _verify_content_seal(approval, "approval_payload_content_sha256")
    proposal_file_sha256 = _sha256_file(proposal_path)

    if (
        proposal.get("schema") != PROPOSAL_SCHEMA
        or proposal.get("status") != "PROPOSED_NOT_OWNER_APPROVED"
        or proposal.get("authoritative") is not False
        or proposal.get("owner_approval_recorded") is not False
        or proposal.get("item_count") != sum(EXPECTED_CATEGORY_COUNTS.values())
        or proposal.get("category_counts") != EXPECTED_CATEGORY_COUNTS
    ):
        raise ValueError("phase2a_owner_approval_proposal_boundary_invalid")
    if (
        approval.get("schema") != APPROVAL_REQUEST_SCHEMA
        or approval.get("status") != "AWAITING_EXPLICIT_OWNER_REPLY"
        or approval.get("proposal_content_sha256") != proposal_seal
        or approval.get("proposed_decisions_file_sha256") != proposal_file_sha256
        or approval.get("owner_typed_name") != proposal.get("owner_typed_name")
        or approval.get("owner_decision_date") != proposal.get("owner_decision_date")
        or approval.get("requested_reply") != owner_reply
        or owner_reply != "OK"
    ):
        raise ValueError("phase2a_owner_approval_reply_binding_invalid")
    if approval.get("not_authorized_by_reply") != {
        "automatic_source_admission_indexing_or_embedding": True,
        "development30_execution": True,
        "phase2b_execution": True,
        "treat_more_evidence_as_pass": True,
        "validation_promotion_or_live": True,
    }:
        raise ValueError("phase2a_owner_approval_forbidden_scope_invalid")

    source_items = _load_source_items(source_review_root)
    approved_entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    outcomes: Counter[str] = Counter()
    for entry in proposal.get("entries", []):
        key = (str(entry.get("category") or ""), str(entry.get("item_id") or ""))
        if key in seen or key not in source_items:
            raise ValueError("phase2a_owner_approval_proposal_item_invalid")
        seen.add(key)
        item = source_items[key]
        if (
            entry.get("item_sha256") != item.get("item_sha256")
            or entry.get("source_record_sha256") != item.get("source_record_sha256")
        ):
            raise ValueError("phase2a_owner_approval_proposal_item_binding_invalid")
        advisory = owner_review.validate_advisory_ai_review(entry["advisory_ai_review"])
        decision = owner_review.validate_owner_decision(
            item=item,
            decision=entry["proposed_owner_decision"],
            advisory_ai_review=advisory,
        )
        outcomes[str(decision["owner_outcome"])] += 1
        approved_entries.append(
            {
                "category": key[0],
                "item_id": key[1],
                "item_sha256": item["item_sha256"],
                "source_record_sha256": item["source_record_sha256"],
                "owner_decision": decision,
                "advisory_ai_review": advisory,
            }
        )
    if seen != set(source_items) or len(approved_entries) != sum(EXPECTED_CATEGORY_COUNTS.values()):
        raise ValueError("phase2a_owner_approval_decision_inventory_invalid")
    if outcomes != Counter(
        {"APPROVE_EFFECT_DISPOSITION": 1380, "REQUEST_MORE_EVIDENCE": 1189}
    ):
        raise ValueError("phase2a_owner_approval_outcome_inventory_invalid")

    receipt_material: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "status": "OWNER_APPROVED_PHASE2A_ONLY",
        "owner_typed_name": approval["owner_typed_name"],
        "owner_decision_date": approval["owner_decision_date"],
        "owner_reply": owner_reply,
        "recorded_at": recorded_at.astimezone(UTC).isoformat(timespec="seconds"),
        "approval_payload_content_sha256": approval_seal,
        "approval_request_file_sha256": _sha256_file(approval_request_path),
        "proposal_content_sha256": proposal_seal,
        "proposal_file_sha256": proposal_file_sha256,
        "source_phase2a_package_digest": proposal["source_phase2a_package_digest"],
        "source_owner_review_package_digest": proposal[
            "source_owner_review_package_digest"
        ],
        "decision_count": len(approved_entries),
        "outcome_counts": dict(sorted(outcomes.items())),
        "authority": {
            "continued_phase2a_remediation": True,
            "official_source_retrieval_to_quarantine": True,
            "one_consolidated_successor_candidate_if_proven_required": True,
            "phase2a_reverification_and_requalification": True,
            "automatic_source_admission_indexing_or_embedding": False,
            "phase2b_execution": False,
            "development30_execution": False,
            "validation_promotion_or_live": False,
        },
    }
    receipt_seal = _sha256_bytes(_canonical_json(receipt_material))
    receipt = {**receipt_material, "receipt_content_sha256": receipt_seal}

    approved_material: dict[str, Any] = {
        "schema": APPROVED_PACKAGE_SCHEMA,
        "status": "OWNER_DECISIONS_APPROVED_PHASE2A_ONLY",
        "authoritative_owner_record": True,
        "owner_approval_receipt_content_sha256": receipt_seal,
        "source_proposal_content_sha256": proposal_seal,
        "source_phase2a_package_digest": proposal["source_phase2a_package_digest"],
        "source_owner_review_package_digest": proposal[
            "source_owner_review_package_digest"
        ],
        "item_count": len(approved_entries),
        "category_counts": EXPECTED_CATEGORY_COUNTS,
        "outcome_counts": dict(sorted(outcomes.items())),
        "phase2b_authorized": False,
        "development30_authorized": False,
        "entries": approved_entries,
    }
    approved_seal = _sha256_bytes(_canonical_json(approved_material))
    approved_package = {
        **approved_material,
        "approved_package_content_sha256": approved_seal,
    }

    receipt_path = output_root / "OWNER-APPROVAL-RECEIPT.json"
    decisions_path = output_root / "OWNER-DECISIONS-APPROVED.json"
    outcome_path = output_root / "OUTCOME.txt"
    _write_exclusive(receipt_path, _pretty_json(receipt))
    _write_exclusive(decisions_path, _pretty_json(approved_package))
    _write_exclusive(
        outcome_path,
        (
            "PHASE 2A OWNER DECISIONS RECORDED — CONTINUED PHASE 2A REMEDIATION "
            "AUTHORIZED; PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED\n"
        ).encode(),
    )
    hashes = {
        path.name: _sha256_file(path)
        for path in (receipt_path, decisions_path, outcome_path)
    }
    sums_path = output_root / "SHA256SUMS.txt"
    _write_exclusive(
        sums_path,
        "".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items())).encode(
            "utf-8"
        ),
    )
    return {
        "owner_approval_receipt": str(receipt_path),
        "owner_approval_receipt_content_sha256": receipt_seal,
        "approved_decisions": str(decisions_path),
        "approved_decisions_content_sha256": approved_seal,
        "item_count": len(approved_entries),
        "outcome_counts": dict(sorted(outcomes.items())),
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        failure_path = output_root / "FAILURE.json"
        if failure_path.exists():
            return
        material = {
            "schema": "legalbot.v111.phase2a.owner-approval-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            failure_path,
            _pretty_json({**material, "failure_content_sha256": _sha256_bytes(_canonical_json(material))}),
        )
    except Exception:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--approval-request", type=Path, required=True)
    parser.add_argument("--source-review-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--owner-reply", required=True)
    parser.add_argument("--recorded-at", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        recorded_at = datetime.fromisoformat(str(args.recorded_at).replace("Z", "+00:00"))
        if recorded_at.tzinfo is None:
            raise ValueError("phase2a_owner_approval_recorded_at_naive")
        result = apply_owner_approval(
            proposal_path=args.proposal.resolve(strict=True),
            approval_request_path=args.approval_request.resolve(strict=True),
            source_review_root=args.source_review_root.resolve(strict=True),
            output_root=args.output_root.resolve(),
            owner_reply=str(args.owner_reply),
            recorded_at=recorded_at,
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
