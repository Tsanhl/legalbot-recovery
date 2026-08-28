#!/usr/bin/env python3
"""Apply Agnes's exact 580-item Phase-2A safe-subset decision.

The command is create-only. It verifies the complete r47 machine package and
the exact owner-decision digest, records 516 metadata/currentness-only effect
decisions and 64 nonmaterial representation-byte decisions, and carries the
remaining 478 substantive items forward unchanged. It never admits a source,
indexes, embeds, mutates a candidate, qualifies an issue, or authorizes a later
phase.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2a-owner-review"
    / "LegalBot-Phase2AB-2026-08-25-r49-safe-subset-approved"
)
EXPECTED_DECISION_BATCH_DIGEST = "7a471bed936bf901cca49413f1abb8e27db54157862a1f369136a0704e811414"
EXPECTED_MACHINE_PACKAGE_DIGEST = "3ba8de75875cd2192a0707450c206fbb91220fbf3d3ac2704b1fd18046d1227c"
EXPECTED_OWNER_REPLY = (
    "I, Agnes, approve the exact 516 legislative-effect metadata/currentness-only "
    "recommendations and the exact 64 semantic-text-identical byte-mismatch "
    "recommendations bound to Phase-2A owner-decision batch digest "
    f"{EXPECTED_DECISION_BATCH_DIGEST}. This approval is for continued Phase 2A "
    "only. It does not approve the 448 issue proposition/span selections, the 20 "
    "judgment later-treatment decisions, the Patents Act 1977 section 60(7) text "
    "delta, or the 9 new source admissions. It does not authorize Phase 2B or "
    "Development 30."
)
EXPECTED_SOURCE_COUNTS = {
    "issue": 448,
    "judgment": 20,
    "legislation_byte_mismatch": 65,
    "legislative_effect": 516,
    "source_admission": 9,
}
EXPECTED_REMAINING_COUNTS = {
    "issue": 448,
    "judgment": 20,
    "legislation_byte_mismatch": 1,
    "source_admission": 9,
}
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
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_safe_subset_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_safe_subset_input_must_be_object")
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


def _sealed_artifact(schema: str, material: Mapping[str, Any]) -> dict[str, Any]:
    payload = {"schema": schema, **material}
    return {**payload, "artifact_content_sha256": _sealed(payload)}


def _verify_source_package(source_root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    index = _load_object(source_root / "MACHINE-PACKAGE-INDEX.json")
    index_digest = _verify_seal(
        index,
        "machine_package_content_sha256",
        "phase2a_safe_subset_machine_index_seal_invalid",
    )
    if (
        index_digest != EXPECTED_MACHINE_PACKAGE_DIGEST
        or index.get("phase2b_authorized") is not False
        or index.get("development30_authorized") is not False
        or index.get("candidate_mutated") is not False
    ):
        raise ValueError("phase2a_safe_subset_machine_index_boundary_invalid")
    files = index.get("files")
    if not isinstance(files, dict):
        raise ValueError("phase2a_safe_subset_machine_file_index_invalid")
    for name, expected in files.items():
        path = source_root / str(name)
        if (
            path.parent != source_root
            or path.is_symlink()
            or not path.is_file()
            or not isinstance(expected, dict)
            or _sha256_file(path) != expected.get("sha256")
            or path.stat().st_size != expected.get("bytes")
        ):
            raise ValueError("phase2a_safe_subset_machine_file_invalid")
    for line in (source_root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        path = source_root / name
        if not _SHA256.fullmatch(digest) or _sha256_file(path) != digest:
            raise ValueError("phase2a_safe_subset_machine_checksums_invalid")

    decision_path = source_root / "OWNER-DECISION-BATCH-1058.json"
    decision = _load_object(decision_path)
    decision_digest = _verify_seal(
        decision,
        "owner_decision_batch_content_sha256",
        "phase2a_safe_subset_decision_batch_seal_invalid",
    )
    items = decision.get("items")
    if (
        decision_digest != EXPECTED_DECISION_BATCH_DIGEST
        or decision.get("schema") != "legalbot.v111.phase2a.consolidated-owner-decision-batch.v1"
        or decision.get("item_count") != 1058
        or decision.get("category_counts") != EXPECTED_SOURCE_COUNTS
        or decision.get("immediately_approvable_deterministic_recommendation_count") != 580
        or decision.get("owner_decisions_applied") is not False
        or decision.get("source_admission_authorized") is not False
        or decision.get("candidate_mutated") is not False
        or decision.get("phase2b_authorized") is not False
        or decision.get("development30_authorized") is not False
        or not isinstance(items, list)
        or len(items) != 1058
    ):
        raise ValueError("phase2a_safe_subset_decision_batch_boundary_invalid")
    return decision, items


def _classify_items(
    items: Sequence[dict[str, Any]], immediately_approvable: Sequence[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    effects: list[dict[str, Any]] = []
    mismatches: list[dict[str, Any]] = []
    remaining: list[dict[str, Any]] = []
    derived_approvable: list[str] = []
    seen: set[str] = set()
    for item in items:
        item_digest = _verify_seal(
            item,
            "record_content_sha256",
            "phase2a_safe_subset_item_seal_invalid",
        )
        if item_digest in seen:
            raise ValueError("phase2a_safe_subset_duplicate_item")
        seen.add(item_digest)
        category = str(item.get("category") or "")
        if category == "legislative_effect":
            if (
                item.get("recommendation")
                != "RECOMMEND_METADATA_ONLY_PENDING_FINAL_PROPOSITION_BINDING_CONFIRMATION"
                or item.get("recommendation_scope")
                != "METADATA_OR_CURRENTNESS_ONLY_PENDING_FINAL_PROPOSITION_BINDING"
                or item.get("owner_outcome") is not None
            ):
                raise ValueError("phase2a_safe_subset_effect_boundary_invalid")
            effects.append(item)
            derived_approvable.append(item_digest)
        elif (
            category == "legislation_byte_mismatch"
            and item.get("classification") == "SEMANTIC_PROVISION_TEXT_IDENTICAL_BYTE_MISMATCH_ONLY"
        ):
            if (
                item.get("recommendation") != "APPROVE_NONMATERIAL_REPRESENTATION_BYTE_MISMATCH"
                or item.get("changed_locators") != []
                or item.get("owner_outcome") is not None
            ):
                raise ValueError("phase2a_safe_subset_mismatch_boundary_invalid")
            mismatches.append(item)
            derived_approvable.append(item_digest)
        else:
            remaining.append(item)
    if (
        len(effects) != 516
        or len(mismatches) != 64
        or len(remaining) != 478
        or list(immediately_approvable) != derived_approvable
        or Counter(str(item.get("category") or "") for item in remaining)
        != Counter(EXPECTED_REMAINING_COUNTS)
    ):
        raise ValueError("phase2a_safe_subset_count_invariant_failed")
    return effects, mismatches, remaining


def _approved_record(
    item: Mapping[str, Any], *, owner_outcome: str, decision_date: str
) -> dict[str, Any]:
    source_digest = str(item["record_content_sha256"])
    material = {
        "schema": "legalbot.v111.phase2a.safe-subset-owner-approved-item.v1",
        "status": "OWNER_DECISION_RECORDED_CONTINUED_PHASE2A_ONLY",
        "category": item["category"],
        "item_id": item["item_id"],
        "source_item_content_sha256": source_digest,
        "source_item": dict(item),
        "owner_typed_name": "Agnes",
        "owner_decision_date": decision_date,
        "owner_outcome": owner_outcome,
        "owner_comments": None,
        "internal_research_tool_only": True,
        "professional_legal_certification": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "approved_item_content_sha256": _sealed(material)}


def _write_package(output_root: Path, files: Mapping[str, bytes]) -> str:
    for name, raw in files.items():
        _write_exclusive(output_root / name, raw)
    entries = {
        name: {"sha256": _sha256(raw), "bytes": len(raw)} for name, raw in sorted(files.items())
    }
    material = {
        "schema": "legalbot.v111.phase2a.safe-subset-owner-approved-index.v1",
        "status": "580_OWNER_DECISIONS_RECORDED_478_SUBSTANTIVE_DECISIONS_REMAIN",
        "file_count": len(entries),
        "files": entries,
        "source_owner_decision_batch_content_sha256": EXPECTED_DECISION_BATCH_DIGEST,
        "approved_decision_count": 580,
        "remaining_substantive_decision_count": 478,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    index = {**material, "package_content_sha256": _sealed(material)}
    _write_exclusive(output_root / "PACKAGE-INDEX.json", _pretty_json(index))
    checksummed = sorted(path for path in output_root.iterdir() if path.is_file())
    sums = "".join(f"{_sha256_file(path)}  {path.name}\n" for path in checksummed)
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return str(index["package_content_sha256"])


def apply_safe_subset(
    *,
    source_root: Path,
    output_root: Path,
    owner_reply: str,
    owner_decision_date: str,
    recorded_at: datetime,
) -> dict[str, Any]:
    """Record the exact safe-subset decision without advancing a later gate."""

    if owner_reply != EXPECTED_OWNER_REPLY:
        raise ValueError("phase2a_safe_subset_owner_reply_not_exact")
    if owner_decision_date != "2026-08-25":
        raise ValueError("phase2a_safe_subset_owner_decision_date_invalid")
    if recorded_at.tzinfo is None:
        raise ValueError("phase2a_safe_subset_recorded_at_naive")
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_safe_subset_output_already_exists")

    decision, items = _verify_source_package(source_root)
    approvable = decision.get("immediately_approvable_item_content_sha256s")
    if not isinstance(approvable, list) or any(not isinstance(value, str) for value in approvable):
        raise ValueError("phase2a_safe_subset_approvable_inventory_invalid")
    effects, mismatches, remaining = _classify_items(items, approvable)

    approved_effects = [
        _approved_record(
            item,
            owner_outcome="APPROVE_METADATA_OR_CURRENTNESS_ONLY_DISPOSITION",
            decision_date=owner_decision_date,
        )
        for item in effects
    ]
    approved_mismatches = [
        _approved_record(
            item,
            owner_outcome="APPROVE_NONMATERIAL_REPRESENTATION_BYTE_MISMATCH",
            decision_date=owner_decision_date,
        )
        for item in mismatches
    ]
    approved_effects.sort(key=lambda item: str(item["item_id"]))
    approved_mismatches.sort(key=lambda item: str(item["item_id"]))

    recorded = recorded_at.astimezone(UTC).isoformat(timespec="seconds")
    receipt = _sealed_artifact(
        "legalbot.v111.phase2a.safe-subset-owner-approval-receipt.v1",
        {
            "status": "OWNER_APPROVED_EXACT_580_SAFE_SUBSET_PHASE2A_ONLY",
            "owner_typed_name": "Agnes",
            "owner_decision_date": owner_decision_date,
            "owner_reply": owner_reply,
            "owner_reply_sha256": _sha256((owner_reply + "\n").encode()),
            "recorded_at": recorded,
            "source_owner_decision_batch_content_sha256": EXPECTED_DECISION_BATCH_DIGEST,
            "source_machine_package_content_sha256": EXPECTED_MACHINE_PACKAGE_DIGEST,
            "approved_legislative_effect_count": 516,
            "approved_semantic_text_identical_byte_mismatch_count": 64,
            "remaining_substantive_decision_count": 478,
            "continued_phase2a_authorized": True,
            "source_admission_authorized": False,
            "candidate_build_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    effect_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.owner-approved-legislative-effects-516.v1",
        {
            "status": "516_METADATA_CURRENTNESS_ONLY_DECISIONS_RECORDED",
            "source_owner_decision_batch_content_sha256": EXPECTED_DECISION_BATCH_DIGEST,
            "record_count": len(approved_effects),
            "records": approved_effects,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    mismatch_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.owner-approved-byte-mismatches-64.v1",
        {
            "status": "64_NONMATERIAL_REPRESENTATION_BYTE_DECISIONS_RECORDED",
            "source_owner_decision_batch_content_sha256": EXPECTED_DECISION_BATCH_DIGEST,
            "record_count": len(approved_mismatches),
            "records": approved_mismatches,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    remaining_artifact = _sealed_artifact(
        "legalbot.v111.phase2a.remaining-substantive-owner-decisions-478.v1",
        {
            "status": "EXACT_OWNER_DECISIONS_REQUIRED_CONTINUED_PHASE2A_ONLY",
            "source_owner_decision_batch_content_sha256": EXPECTED_DECISION_BATCH_DIGEST,
            "item_count": len(remaining),
            "category_counts": EXPECTED_REMAINING_COUNTS,
            "items": remaining,
            "owner_decisions_applied": False,
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )
    inventory = _sealed_artifact(
        "legalbot.v111.phase2a.post-safe-subset-inventory.v1",
        {
            "status": "580_RECORDED_478_SUBSTANTIVE_OWNER_DECISIONS_REMAIN",
            "source_owner_decision_batch_content_sha256": EXPECTED_DECISION_BATCH_DIGEST,
            "owner_approval_receipt_content_sha256": receipt["artifact_content_sha256"],
            "total_issue_count": 585,
            "recorded_issue_count": 137,
            "pending_issue_count": 448,
            "total_legislative_effect_count": 1896,
            "recorded_legislative_effect_count": 1896,
            "pending_legislative_effect_count": 0,
            "total_judgment_count": 20,
            "pending_judgment_count": 20,
            "total_byte_mismatch_count": 65,
            "recorded_byte_mismatch_count": 64,
            "pending_byte_mismatch_count": 1,
            "pending_source_admission_count": 9,
            "remaining_substantive_decision_count": 478,
            "common_cutoff_supportable": False,
            "source_admission_authorized": False,
            "successor_candidate_built": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "terminal_verdict": (
                "PHASE 2A CONTINUES WITH 478 SUBSTANTIVE OWNER DECISIONS REQUIRED — "
                "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
            ),
        },
    )

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_safe_subset_output_mode_invalid")
    files = {
        "OWNER-APPROVAL-RECEIPT-580.json": _pretty_json(receipt),
        "APPROVED-LEGISLATIVE-EFFECT-DECISIONS-516.json": _pretty_json(effect_artifact),
        "APPROVED-BYTE-MISMATCH-DECISIONS-64.json": _pretty_json(mismatch_artifact),
        "REMAINING-SUBSTANTIVE-OWNER-DECISIONS-478.json": _pretty_json(remaining_artifact),
        "POST-580-PHASE2A-INVENTORY.json": _pretty_json(inventory),
        "OUTCOME.txt": (str(inventory["terminal_verdict"]) + "\n").encode(),
    }
    package_digest = _write_package(output_root, files)
    return {
        "output_root": str(output_root),
        "source_owner_decision_batch_content_sha256": EXPECTED_DECISION_BATCH_DIGEST,
        "owner_approval_receipt_content_sha256": receipt["artifact_content_sha256"],
        "package_content_sha256": package_digest,
        "approved_decision_count": 580,
        "remaining_substantive_decision_count": 478,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists() or path.is_symlink():
            return
        material = {
            "schema": "legalbot.v111.phase2a.safe-subset-application-failure.v1",
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "failure_fingerprint": _sha256(f"{type(exc).__name__}:{exc}".encode()),
            "debug_required_before_any_third_attempt": True,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_exclusive(
            path,
            _pretty_json({**material, "failure_content_sha256": _sealed(material)}),
        )
    except BaseException:
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    output_root = args.output_root.resolve()
    try:
        result = apply_safe_subset(
            source_root=args.source_root.resolve(strict=True),
            output_root=output_root,
            owner_reply=EXPECTED_OWNER_REPLY,
            owner_decision_date="2026-08-25",
            recorded_at=datetime.now(UTC),
        )
    except BaseException as exc:
        _persist_failure(output_root, exc)
        raise
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
