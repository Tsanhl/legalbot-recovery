#!/usr/bin/env python3
"""Apply sealed owner decisions to a new Phase-2A progress package.

The command is create-only and deliberately non-promotional.  It records the
owner review status beside each deterministic evidence record, but it cannot
qualify an issue, admit a source, mutate a candidate, or authorize Phase 2B or
Development 30.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path
from typing import Any

APPROVED_SCHEMA = "legalbot.v111.phase2a.owner-decisions-approved.v1"
RECEIPT_SCHEMA = "legalbot.v111.phase2a.owner-approval-receipt.v1"
EXPECTED_CATEGORY_COUNTS = {
    "issue": 585,
    "legislative_effect": 1896,
    "judgment": 20,
    "source_version": 68,
}
EXPECTED_OUTCOMES = {
    "APPROVE_EFFECT_DISPOSITION": 1380,
    "REQUEST_MORE_EVIDENCE": 1189,
}
EXPECTED_HISTORICAL_REVIEW_SHA256 = (
    "e06d7f1179d58824c16ce2e45cbf46dcdce64365d69652729255738b9ddb1d2d"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sealed(value: Any) -> str:
    return _sha256_bytes(_canonical_json(value))


def _load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_decision_application_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_decision_application_input_must_be_object")
    return value


def _verify_seal(value: dict[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or _sealed(material) != supplied:
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


def _owner_review(entry: dict[str, Any], receipt_sha256: str) -> dict[str, Any]:
    decision = dict(entry["owner_decision"])
    decision_sha256 = _sealed(decision)
    return {
        "status": (
            "OWNER_APPROVED_RECORDED_DISPOSITION"
            if decision["owner_outcome"] == "APPROVE_EFFECT_DISPOSITION"
            else "OWNER_REQUESTED_MORE_EVIDENCE"
        ),
        "owner_outcome": decision["owner_outcome"],
        "owner_typed_name": decision["owner_typed_name"],
        "owner_decision_date": decision["owner_decision_date"],
        "owner_decision_sha256": decision_sha256,
        "owner_approval_receipt_content_sha256": receipt_sha256,
        "item_id": entry["item_id"],
        "item_sha256": entry["item_sha256"],
        "decision_basis_sha256s": decision["decision_basis_sha256s"],
        "findings": decision["findings"],
        "does_not_admit_index_or_embed_source": True,
        "does_not_authorize_phase2b_or_development30": True,
    }


def _source_record_sha256(category: str, record: dict[str, Any]) -> str:
    if category == "issue":
        supplied = str(record.get("row_evidence_sha256") or "")
    elif category in {"legislative_effect", "judgment"}:
        supplied = str(record.get("record_sha256") or "")
    else:
        supplied = str(record.get("sha256") or "")
    return supplied if _SHA256.fullmatch(supplied) else _sealed(record)


def _records_by_sha(category: str, records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for record in records:
        digest = _source_record_sha256(category, record)
        if digest in indexed:
            raise ValueError("phase2a_decision_application_duplicate_source_record")
        indexed[digest] = record
    return indexed


def _apply_category(
    *,
    category: str,
    records: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    receipt_sha256: str,
    require_complete_source_inventory: bool = True,
) -> list[dict[str, Any]]:
    source = _records_by_sha(category, records)
    applied: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        digest = str(entry.get("source_record_sha256") or "")
        if digest in seen or digest not in source:
            raise ValueError("phase2a_decision_application_source_binding_invalid")
        seen.add(digest)
        record = dict(source[digest])
        review = _owner_review(entry, receipt_sha256)
        record["owner_review"] = review
        record["owner_decision_required"] = review["status"] == "OWNER_REQUESTED_MORE_EVIDENCE"
        applied.append(record)
    if (
        (require_complete_source_inventory and seen != set(source))
        or len(applied) != len(entries)
    ):
        raise ValueError("phase2a_decision_application_inventory_incomplete")
    return applied


def _sealed_artifact(
    *, schema: str, records_key: str, records: list[dict[str, Any]], summary: dict[str, Any]
) -> dict[str, Any]:
    material = {
        "schema": schema,
        "record_count": len(records),
        "summary": summary,
        records_key: records,
        "automatic_source_admission": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    return {**material, "artifact_content_sha256": _sealed(material)}


def _historical_recovery_assessment(path: Path | None) -> dict[str, Any]:
    material: dict[str, Any] = {
        "schema": "legalbot.v111.phase2a.historical-review-recovery-assessment.v1",
        "expected_file_sha256": EXPECTED_HISTORICAL_REVIEW_SHA256,
        "file_name": path.name if path is not None else None,
        "found": bool(path is not None and path.is_file() and not path.is_symlink()),
        "observed_file_sha256": None,
        "bytes": None,
        "observed_schema": None,
        "observed_record_count": None,
        "status": "MISSING_NOT_IMPORTED",
        "authoritative": False,
        "imported": False,
        "may_qualify_issue": False,
        "may_admit_index_or_embed_source": False,
    }
    if material["found"]:
        assert path is not None
        observed = _sha256_file(path)
        payload = _load_json(path)
        records = payload.get("records")
        material.update(
            {
                "observed_file_sha256": observed,
                "bytes": path.stat().st_size,
                "observed_schema": payload.get("schema"),
                "observed_record_count": len(records) if isinstance(records, list) else None,
                "status": (
                    "EXACT_HASH_MATCH_STAGING_ONLY"
                    if observed == EXPECTED_HISTORICAL_REVIEW_SHA256
                    else "HASH_MISMATCH_NOT_IMPORTED"
                ),
            }
        )
    return {**material, "assessment_content_sha256": _sealed(material)}


def apply_decisions(
    *,
    approved_path: Path,
    receipt_path: Path,
    remediation_root: Path,
    output_root: Path,
    historical_review_path: Path | None = None,
) -> dict[str, Any]:
    """Create a sealed post-approval progress package without advancing a gate."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_decision_application_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_decision_application_output_mode_invalid")

    approved = _load_json(approved_path)
    receipt = _load_json(receipt_path)
    approved_sha256 = _verify_seal(
        approved,
        "approved_package_content_sha256",
        "phase2a_decision_application_approved_seal_invalid",
    )
    receipt_sha256 = _verify_seal(
        receipt,
        "receipt_content_sha256",
        "phase2a_decision_application_receipt_seal_invalid",
    )
    if (
        approved.get("schema") != APPROVED_SCHEMA
        or receipt.get("schema") != RECEIPT_SCHEMA
        or approved.get("authoritative_owner_record") is not True
        or approved.get("owner_approval_receipt_content_sha256") != receipt_sha256
        or approved.get("category_counts") != EXPECTED_CATEGORY_COUNTS
        or approved.get("outcome_counts") != EXPECTED_OUTCOMES
        or approved.get("phase2b_authorized") is not False
        or approved.get("development30_authorized") is not False
        or receipt.get("authority", {}).get("phase2b_execution") is not False
        or receipt.get("authority", {}).get("development30_execution") is not False
    ):
        raise ValueError("phase2a_decision_application_authority_boundary_invalid")

    source_specs = {
        "issue": ("remediation-matrix-585.json", "artifact_sha256", "rows"),
        "legislative_effect": (
            "legislative-effects-register-1896.json",
            "register_sha256",
            "effects",
        ),
        "judgment": ("judgment-later-treatment-register-20.json", "register_sha256", "records"),
        "source_version": (
            "official-source-provenance-register.json",
            "artifact_sha256",
            "records",
        ),
    }
    source_records: dict[str, list[dict[str, Any]]] = {}
    source_artifact_sha256s: dict[str, str] = {}
    for category, (name, seal_field, records_key) in source_specs.items():
        artifact = _load_json(remediation_root / name)
        source_artifact_sha256s[name] = _verify_seal(
            artifact,
            seal_field,
            "phase2a_decision_application_source_artifact_seal_invalid",
        )
        records = artifact.get(records_key)
        expected_count = EXPECTED_CATEGORY_COUNTS[category]
        count_invalid = (
            len(records) < expected_count
            if category == "source_version" and isinstance(records, list)
            else isinstance(records, list) and len(records) != expected_count
        )
        if not isinstance(records, list) or count_invalid:
            raise ValueError("phase2a_decision_application_source_artifact_count_invalid")
        source_records[category] = records

    entries_by_category: dict[str, list[dict[str, Any]]] = {
        category: [] for category in EXPECTED_CATEGORY_COUNTS
    }
    for entry in approved.get("entries", []):
        category = str(entry.get("category") or "")
        if category not in entries_by_category:
            raise ValueError("phase2a_decision_application_category_invalid")
        entries_by_category[category].append(entry)
    if {key: len(value) for key, value in entries_by_category.items()} != EXPECTED_CATEGORY_COUNTS:
        raise ValueError("phase2a_decision_application_entry_count_invalid")

    applied = {
        category: _apply_category(
            category=category,
            records=source_records[category],
            entries=entries_by_category[category],
            receipt_sha256=receipt_sha256,
            require_complete_source_inventory=category != "source_version",
        )
        for category in EXPECTED_CATEGORY_COUNTS
    }
    outcome_counts = Counter(
        record["owner_review"]["owner_outcome"]
        for records in applied.values()
        for record in records
    )
    if dict(outcome_counts) != EXPECTED_OUTCOMES:
        raise ValueError("phase2a_decision_application_outcome_count_invalid")

    artifacts = {
        "owner-reviewed-issues-585.json": _sealed_artifact(
            schema="legalbot.v111.phase2a.owner-reviewed-issues.v1",
            records_key="rows",
            records=applied["issue"],
            summary={"owner_requested_more_evidence": 585, "technically_qualified": 0},
        ),
        "owner-reviewed-legislative-effects-1896.json": _sealed_artifact(
            schema="legalbot.v111.phase2a.owner-reviewed-legislative-effects.v1",
            records_key="effects",
            records=applied["legislative_effect"],
            summary={
                "owner_approved_recorded_disposition": 1380,
                "owner_requested_more_evidence": 516,
                "common_cutoff_blocking_effects": 516,
            },
        ),
        "owner-reviewed-judgments-20.json": _sealed_artifact(
            schema="legalbot.v111.phase2a.owner-reviewed-judgments.v1",
            records_key="records",
            records=applied["judgment"],
            summary={"owner_requested_more_evidence": 20, "resolved": 0},
        ),
        "owner-reviewed-source-versions-68.json": _sealed_artifact(
            schema="legalbot.v111.phase2a.owner-reviewed-source-versions.v1",
            records_key="records",
            records=applied["source_version"],
            summary={"owner_requested_more_evidence": 68, "materiality_approved": 0},
        ),
    }
    recovery = _historical_recovery_assessment(historical_review_path)
    artifacts["HISTORICAL-REVIEW-RECOVERY-ASSESSMENT.json"] = recovery

    for name, artifact in artifacts.items():
        _write_exclusive(output_root / name, _pretty_json(artifact))

    progress_material = {
        "schema": "legalbot.v111.phase2a.owner-decision-application.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES_MATERIAL_EVIDENCE_HOLDS_REMAIN",
        "approved_decisions_content_sha256": approved_sha256,
        "owner_approval_receipt_content_sha256": receipt_sha256,
        "source_phase2a_package_digest": approved["source_phase2a_package_digest"],
        "source_owner_review_package_digest": approved["source_owner_review_package_digest"],
        "source_artifact_content_sha256s": source_artifact_sha256s,
        "decision_count": sum(EXPECTED_CATEGORY_COUNTS.values()),
        "decision_outcome_counts": EXPECTED_OUTCOMES,
        "owner_approved_effect_disposition_count": 1380,
        "owner_requested_more_evidence_count": 1189,
        "issue_technical_qualification_count": 0,
        "common_cutoff_supportable": False,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation_promotion_or_live_authorized": False,
        "historical_review_recovery_status": recovery["status"],
        "output_artifact_file_sha256s": {
            name: _sha256_file(output_root / name) for name in sorted(artifacts)
        },
        "terminal_verdict": (
            "PHASE 2A SAFELY CONTINUES WITH MATERIAL EVIDENCE HOLDS — "
            "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
        ),
    }
    progress = {
        **progress_material,
        "application_content_sha256": _sealed(progress_material),
    }
    _write_exclusive(output_root / "OWNER-DECISION-APPLICATION.json", _pretty_json(progress))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        (progress["terminal_verdict"] + "\n").encode(),
    )
    checksummed = sorted(path for path in output_root.iterdir() if path.is_file())
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in checksummed).encode(),
    )
    return {
        "output_root": str(output_root),
        "application_content_sha256": progress["application_content_sha256"],
        "owner_approved_effect_disposition_count": 1380,
        "owner_requested_more_evidence_count": 1189,
        "historical_review_recovery_status": recovery["status"],
        "issue_technical_qualification_count": 0,
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
            "schema": "legalbot.v111.phase2a.owner-decision-application-failure.v1",
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
    parser.add_argument("--approved-decisions", required=True, type=Path)
    parser.add_argument("--approval-receipt", required=True, type=Path)
    parser.add_argument("--remediation-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--historical-review", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = apply_decisions(
            approved_path=args.approved_decisions.resolve(strict=True),
            receipt_path=args.approval_receipt.resolve(strict=True),
            remediation_root=args.remediation_root.resolve(strict=True),
            output_root=args.output_root.resolve(),
            historical_review_path=(
                args.historical_review.resolve(strict=True) if args.historical_review else None
            ),
        )
    except Exception as exc:
        _persist_failure(args.output_root.resolve(), exc)
        raise
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
