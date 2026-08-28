#!/usr/bin/env python3
"""Record Agnes's exact r94 Phase-2A substantive owner approval.

This create-only command verifies the sealed r94 package, records only the
decisions and 20 source admissions named by that package, and carries the 364
unresolved material-gap rows forward unchanged. It never indexes, embeds,
mutates a candidate, qualifies an issue, or authorizes Phase 2B/Development 30.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_SOURCE_ROOT = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r94-consolidated-substantive-owner-batch"
)
DEFAULT_PREDECESSOR_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r49-safe-subset-approved"
)
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r95-substantive-owner-approved"
)
EXPECTED_BATCH_DIGEST = (
    "496c36b665b8114f6ba44169d23f911ec31fc2718aecb1747b2e26962bd889f7"
)
EXPECTED_PACKAGE_DIGEST = (
    "f64df56bad4a155b66b023ccdb90ecff8bcb639fa4c80e93757a8f5a72434c7c"
)
EXPECTED_PREDECESSOR_PACKAGE_DIGEST = (
    "ef6d4fff911ba6320fa0e7adfadc7af934179432b2c6889c498a76f6ecc1eeba"
)
EXPECTED_COUNTS = {
    "candidate_exact_binding_decision_count": 84,
    "judgment_later_treatment_decision_count": 20,
    "judgment_source_admission_count": 9,
    "supplemental_binding_decision_count": 13,
    "supplemental_unique_source_admission_count": 7,
    "uksc_source_review_decision_count": 5,
    "uksc_source_admission_count": 4,
    "total_unique_source_admission_count": 20,
    "xml_byte_mismatch_disposition_count": 1,
    "patents_delta_deferral_count": 1,
    "unresolved_material_gap_row_count": 364,
}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
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
        raise ValueError("phase2a_r94_approval_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_r94_approval_input_must_be_object")
    return value


def _verify_seal(
    value: Mapping[str, Any], field: str, code: str, expected: str | None = None
) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if (
        not _SHA256.fullmatch(supplied)
        or supplied != _sealed(material)
        or (expected is not None and supplied != expected)
    ):
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


def _verify_decision_seal(item: Mapping[str, Any]) -> None:
    if "decision_content_sha256" not in item:
        return
    _verify_seal(
        item,
        "decision_content_sha256",
        "phase2a_r94_approval_decision_seal_invalid",
    )


def _verify_source_package(
    source_root: Path, predecessor_root: Path
) -> tuple[dict[str, Any], str]:
    package = _load_object(source_root / "PACKAGE-MANIFEST.json")
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_r94_approval_package_seal_invalid",
        EXPECTED_PACKAGE_DIGEST,
    )
    batch_path = source_root / "OWNER-SUBSTANTIVE-DECISION-BATCH.json"
    prompt_path = source_root / "OWNER-APPROVAL-PROMPT.txt"
    if (
        package.get("owner_batch_content_sha256") != EXPECTED_BATCH_DIGEST
        or package.get("owner_batch_file_sha256") != _sha256_file(batch_path)
        or package.get("owner_approval_prompt_file_sha256") != _sha256_file(prompt_path)
        or package.get("owner_approved") is not False
        or package.get("source_admission_authorized") is not False
        or package.get("candidate_mutated") is not False
        or package.get("phase2b_authorized") is not False
        or package.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r94_approval_package_boundary_invalid")

    batch = _load_object(batch_path)
    _verify_seal(
        batch,
        "artifact_content_sha256",
        "phase2a_r94_approval_batch_seal_invalid",
        EXPECTED_BATCH_DIGEST,
    )
    if (
        batch.get("schema")
        != "legalbot.v111.phase2a.consolidated-substantive-owner-batch.v1"
        or batch.get("decision_summary") != EXPECTED_COUNTS
        or batch.get("owner") != "Agnes"
        or batch.get("decision_date") != "2026-08-25"
        or batch.get("owner_approved") is not False
        or batch.get("source_admission_authorized") is not False
        or batch.get("automatic_indexing") is not False
        or batch.get("automatic_embedding") is not False
        or batch.get("candidate_mutated") is not False
        or batch.get("technical_qualification_assigned") is not False
        or batch.get("phase2b_authorized") is not False
        or batch.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r94_approval_batch_boundary_invalid")

    inventories = {
        "candidate_exact_binding_decisions": 84,
        "judgment_later_treatment_decisions": 20,
        "judgment_source_admission_decisions": 9,
        "supplemental_binding_and_source_decisions": 13,
        "uksc_source_review_decisions": 5,
        "unresolved_material_gap_rows": 364,
    }
    for field, count in inventories.items():
        rows = batch.get(field)
        if not isinstance(rows, list) or len(rows) != count:
            raise ValueError("phase2a_r94_approval_inventory_invalid")
        for item in rows:
            if not isinstance(item, dict):
                raise ValueError("phase2a_r94_approval_inventory_invalid")
            _verify_decision_seal(item)
            if "owner_outcome" in item and item.get("owner_outcome") is not None:
                raise ValueError("phase2a_r94_approval_owner_outcome_already_assigned")
    row_ids = [str(item["row_id"]) for item in batch["unresolved_material_gap_rows"]]
    if len(set(row_ids)) != 364:
        raise ValueError("phase2a_r94_approval_unresolved_row_inventory_invalid")

    predecessor = _load_object(predecessor_root / "PACKAGE-INDEX.json")
    _verify_seal(
        predecessor,
        "package_content_sha256",
        "phase2a_r94_approval_predecessor_seal_invalid",
        EXPECTED_PREDECESSOR_PACKAGE_DIGEST,
    )
    if (
        predecessor.get("approved_decision_count") != 580
        or predecessor.get("phase2b_authorized") is not False
        or predecessor.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_r94_approval_predecessor_boundary_invalid")
    expected_reply = prompt_path.read_text(encoding="utf-8").strip()
    return batch, expected_reply


def _approved_decision(kind: str, item: Mapping[str, Any]) -> dict[str, Any]:
    recommended = item.get("recommended_owner_outcome")
    if not isinstance(recommended, str) or not recommended:
        raise ValueError("phase2a_r94_approval_recommendation_missing")
    material = {
        "schema": "legalbot.v111.phase2a.r94-owner-approved-decision.v1",
        "status": "OWNER_DECISION_RECORDED_CONTINUED_PHASE2A_ONLY",
        "decision_kind": kind,
        "source_decision_content_sha256": _sealed(item),
        "source_decision": dict(item),
        "owner_typed_name": "Agnes",
        "owner_decision_date": "2026-08-25",
        "owner_outcome": recommended,
        "technical_qualification_assigned": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "approved_decision_content_sha256": _sealed(material)}


def _source_admissions(batch: Mapping[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in batch["judgment_source_admission_decisions"]:
        records.append(
            {
                "source_key": f"judgment:{item['neutral_citation']}",
                "source_group": "JUDGMENT_LATER_TREATMENT",
                "source_identity": item["neutral_citation"],
                "proposition_level_uses": [item["proposal_id"]],
                "source_decision_content_sha256s": [_sealed(item)],
            }
        )

    supplemental: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in batch["supplemental_binding_and_source_decisions"]:
        if item.get("owner_source_admission_required") is True:
            supplemental[str(item["source_target_id"])].append(item)
    for source_id, items in sorted(supplemental.items()):
        records.append(
            {
                "source_key": f"official-legislation:{source_id}",
                "source_group": "SUPPLEMENTAL_OFFICIAL_LEGISLATION",
                "source_identity": source_id,
                "proposition_level_uses": sorted(
                    {str(row_id) for item in items for row_id in item["row_ids"]}
                ),
                "source_decision_content_sha256s": sorted(_sealed(item) for item in items),
            }
        )

    for item in batch["uksc_source_review_decisions"]:
        if item["recommended_owner_outcome"] == "APPROVE_PROPOSITION_BINDINGS_AND_SOURCE_ADMISSION":
            records.append(
                {
                    "source_key": f"uksc:{item['neutral_citation']}",
                    "source_group": "UKSC_JUDGMENT",
                    "source_identity": item["neutral_citation"],
                    "proposition_level_uses": item[
                        "supported_claim_binding_content_sha256s"
                    ],
                    "source_decision_content_sha256s": [_sealed(item)],
                }
            )

    if len(records) != 20 or len({row["source_key"] for row in records}) != 20:
        raise ValueError("phase2a_r94_approval_source_admission_count_invalid")
    sealed_records = []
    for record in sorted(records, key=lambda row: row["source_key"]):
        material = {
            **record,
            "status": "OWNER_APPROVED_FOR_LATER_CONSOLIDATED_SUCCESSOR_SCOPE",
            "owner_typed_name": "Agnes",
            "owner_decision_date": "2026-08-25",
            "source_admission_authorized": True,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_build_authorized": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        sealed_records.append(
            {**material, "source_admission_content_sha256": _sealed(material)}
        )
    return sealed_records


def _write_package(output_root: Path, files: Mapping[str, bytes]) -> str:
    for name, raw in files.items():
        _write_exclusive(output_root / name, raw)
    entries = {
        name: {"sha256": _sha256(raw), "bytes": len(raw)}
        for name, raw in sorted(files.items())
    }
    material = {
        "schema": "legalbot.v111.phase2a.r94-owner-approved-package.v1",
        "status": "R94_OWNER_DECISIONS_RECORDED_364_MATERIAL_GAPS_REMAIN",
        "file_count": len(entries),
        "files": entries,
        "source_r94_batch_content_sha256": EXPECTED_BATCH_DIGEST,
        "source_r94_package_content_sha256": EXPECTED_PACKAGE_DIGEST,
        "predecessor_safe_subset_package_content_sha256": (
            EXPECTED_PREDECESSOR_PACKAGE_DIGEST
        ),
        "approved_candidate_binding_count": 84,
        "approved_judgment_disposition_count": 20,
        "approved_source_admission_count": 20,
        "remaining_material_gap_count": 364,
        "automatic_indexing": False,
        "automatic_embedding": False,
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


def apply_approval(
    *,
    source_root: Path,
    predecessor_root: Path,
    output_root: Path,
    owner_reply: str,
    owner_decision_date: str,
    recorded_at: datetime,
) -> dict[str, Any]:
    """Record the exact r94 owner approval without advancing a later gate."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_r94_approval_output_already_exists")
    if owner_decision_date != "2026-08-25":
        raise ValueError("phase2a_r94_approval_owner_decision_date_invalid")
    if recorded_at.tzinfo is None:
        raise ValueError("phase2a_r94_approval_recorded_at_naive")
    batch, expected_reply = _verify_source_package(source_root, predecessor_root)
    if owner_reply != expected_reply:
        raise ValueError("phase2a_r94_approval_owner_reply_not_exact")

    candidate = [
        _approved_decision("CANDIDATE_PROPOSITION_EXACT_SPAN", item)
        for item in batch["candidate_exact_binding_decisions"]
    ]
    judgments = [
        _approved_decision("JUDGMENT_LATER_TREATMENT", item)
        for item in batch["judgment_later_treatment_decisions"]
    ]
    supplemental = [
        _approved_decision("SUPPLEMENTAL_BINDING", item)
        for item in batch["supplemental_binding_and_source_decisions"]
    ]
    uksc = [
        _approved_decision("UKSC_SOURCE_REVIEW", item)
        for item in batch["uksc_source_review_decisions"]
    ]
    source_admissions = _source_admissions(batch)

    recorded = recorded_at.astimezone(UTC).isoformat(timespec="seconds")
    receipt = _sealed_artifact(
        "legalbot.v111.phase2a.r94-owner-approval-receipt.v1",
        {
            "status": "OWNER_APPROVED_EXACT_R94_SUBSTANTIVE_BATCH_PHASE2A_ONLY",
            "owner_typed_name": "Agnes",
            "owner_decision_date": owner_decision_date,
            "owner_reply": owner_reply,
            "owner_reply_sha256": _sha256((owner_reply + "\n").encode()),
            "recorded_at": recorded,
            "source_r94_batch_content_sha256": EXPECTED_BATCH_DIGEST,
            "source_r94_package_content_sha256": EXPECTED_PACKAGE_DIGEST,
            "approved_candidate_binding_count": 84,
            "approved_judgment_disposition_count": 20,
            "approved_source_admission_count": 20,
            "remaining_material_gap_count": 364,
            "continued_phase2a_authorized": True,
            "automatic_indexing": False,
            "automatic_embedding": False,
            "candidate_build_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        },
    )

    artifacts = {
        "APPROVED-CANDIDATE-BINDINGS-84.json": _sealed_artifact(
            "legalbot.v111.phase2a.owner-approved-candidate-bindings-84.v1",
            {"record_count": 84, "records": candidate, "technical_qualification_assigned": False},
        ),
        "APPROVED-JUDGMENT-DISPOSITIONS-20.json": _sealed_artifact(
            "legalbot.v111.phase2a.owner-approved-judgment-dispositions-20.v1",
            {"record_count": 20, "records": judgments, "technical_qualification_assigned": False},
        ),
        "APPROVED-SUPPLEMENTAL-BINDINGS-13.json": _sealed_artifact(
            "legalbot.v111.phase2a.owner-approved-supplemental-bindings-13.v1",
            {"record_count": 13, "records": supplemental, "technical_qualification_assigned": False},
        ),
        "APPROVED-UKSC-SOURCE-REVIEWS-5.json": _sealed_artifact(
            "legalbot.v111.phase2a.owner-approved-uksc-source-reviews-5.v1",
            {"record_count": 5, "records": uksc, "technical_qualification_assigned": False},
        ),
        "APPROVED-SOURCE-ADMISSIONS-20.json": _sealed_artifact(
            "legalbot.v111.phase2a.owner-approved-source-admissions-20.v1",
            {
                "record_count": 20,
                "records": source_admissions,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "candidate_build_authorized": False,
            },
        ),
        "APPROVED-XML-BYTE-MISMATCH-DISPOSITION.json": _sealed_artifact(
            "legalbot.v111.phase2a.owner-approved-xml-byte-mismatch-disposition.v1",
            {
                "source_decision": batch["xml_byte_mismatch_decision"],
                "owner_outcome": "APPROVE_NONMATERIAL_XML_SERIALIZATION_ONLY_DISPOSITION",
                "technical_qualification_assigned": False,
            },
        ),
        "DEFERRED-PATENTS-S60-7-DISPOSITION.json": _sealed_artifact(
            "legalbot.v111.phase2a.owner-approved-patents-s60-7-deferral.v1",
            {
                "source_decision": batch["patents_delta_decision"],
                "owner_outcome": "DEFER_OWNER_OUTCOME_UNTIL_FINAL_PATENTS_PROPOSITION_BINDINGS",
                "final_owner_decision_required": True,
            },
        ),
        "REMAINING-MATERIAL-GAPS-364.json": _sealed_artifact(
            "legalbot.v111.phase2a.remaining-material-gaps-364.v1",
            {
                "status": "OFFICIAL_SOURCE_RESEARCH_AND_OWNER_DECISIONS_REMAIN_REQUIRED",
                "record_count": 364,
                "records": batch["unresolved_material_gap_rows"],
                "owner_approved": False,
                "technical_qualification_assigned": False,
            },
        ),
    }
    inventory = _sealed_artifact(
        "legalbot.v111.phase2a.post-r94-owner-approval-inventory.v1",
        {
            "status": "R94_RECORDED_364_MATERIAL_GAPS_REMAIN",
            "source_r94_batch_content_sha256": EXPECTED_BATCH_DIGEST,
            "owner_approval_receipt_content_sha256": receipt["artifact_content_sha256"],
            "total_issue_count": 585,
            "recorded_issue_count": 221,
            "pending_issue_count": 364,
            "recorded_legislative_effect_count": 1896,
            "pending_legislative_effect_count": 0,
            "recorded_judgment_disposition_count": 20,
            "pending_judgment_disposition_count": 0,
            "recorded_byte_mismatch_count": 65,
            "pending_byte_mismatch_count": 0,
            "approved_r94_source_admission_count": 20,
            "patents_final_decision_pending": True,
            "common_cutoff_supportable": False,
            "successor_candidate_built": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
            "terminal_verdict": (
                "PHASE 2A CONTINUES WITH 364 MATERIAL GAPS — PHASE 2B AND "
                "DEVELOPMENT 30 NOT AUTHORIZED"
            ),
        },
    )

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_r94_approval_output_mode_invalid")
    files: dict[str, bytes] = {
        "OWNER-APPROVAL-RECEIPT-R94.json": _pretty_json(receipt),
        **{name: _pretty_json(value) for name, value in artifacts.items()},
        "POST-R94-PHASE2A-INVENTORY.json": _pretty_json(inventory),
        "OUTCOME.txt": (str(inventory["terminal_verdict"]) + "\n").encode(),
    }
    package_digest = _write_package(output_root, files)
    return {
        "output_root": str(output_root),
        "source_r94_batch_content_sha256": EXPECTED_BATCH_DIGEST,
        "owner_approval_receipt_content_sha256": receipt["artifact_content_sha256"],
        "package_content_sha256": package_digest,
        "approved_candidate_binding_count": 84,
        "approved_judgment_disposition_count": 20,
        "approved_source_admission_count": 20,
        "remaining_material_gap_count": 364,
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
            "schema": "legalbot.v111.phase2a.r94-owner-approval-failure.v1",
            "failure_type": type(exc).__name__,
            "failure_message": str(exc),
            "failure_fingerprint": _sha256(f"{type(exc).__name__}:{exc}".encode()),
            "affected_stage": "PHASE2A_R94_OWNER_APPROVAL_APPLICATION",
            "root_cause_status": "REQUIRES_DEBUG_BEFORE_RETRY",
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=DEFAULT_SOURCE_ROOT)
    parser.add_argument("--predecessor-root", type=Path, default=DEFAULT_PREDECESSOR_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        source_root = args.source_root.resolve(strict=True)
        expected_reply = (source_root / "OWNER-APPROVAL-PROMPT.txt").read_text(
            encoding="utf-8"
        ).strip()
        result = apply_approval(
            source_root=source_root,
            predecessor_root=args.predecessor_root.resolve(strict=True),
            output_root=output_root,
            owner_reply=expected_reply,
            owner_decision_date="2026-08-25",
            recorded_at=datetime.now(UTC),
        )
    except BaseException as exc:
        _persist_failure(output_root, exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
