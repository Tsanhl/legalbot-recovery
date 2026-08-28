#!/usr/bin/env python3
"""Apply the exact owner approval for the sealed 54-row materiality batch.

The command is create-only.  It records the approved proposition bindings and
source-admission scope for continued Phase 2A, but deliberately does not index,
embed, build or mutate a candidate, qualify an issue, or authorize Phase 2B,
Development 30, Validation, promotion, or live activation.
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

BATCH_SCHEMA = "legalbot.v111.phase2a.owner-materiality-batch-54.v1"
EXPECTED_BATCH_DIGEST = "bfaca21d667580b5cd92c916e9ae6c83118e3ccbc82c903ee07a4122ebc7cf37"
EXPECTED_ROW_COUNT = 54
EXPECTED_SOURCE_ADMISSION_ROW_COUNT = 29
EXPECTED_SOURCE_ADMISSION_AUTHORITY_COUNT = 16
EXPECTED_RECOMMENDATION_COUNTS = {
    "APPROVE_CORRECTED_BINDING_AND_REQUIRED_SOURCE_ADMISSION": 27,
    "APPROVE_CORRECTED_BINDING_WITHOUT_SOURCE_ADMISSION": 24,
    "APPROVE_PROPOSITION_BINDING_AND_SOURCE_ADMISSION": 2,
    "APPROVE_PROPOSITION_REBIND_WITHOUT_SOURCE_ADMISSION": 1,
}
EXPECTED_OWNER_REPLY = (
    "OK — I, Agnes, approve all 54 recommendations and proposition-level admission of only "
    "the new official authorities listed in Phase-2A materiality batch digest "
    f"{EXPECTED_BATCH_DIGEST} for continued Phase 2A only."
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


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
        raise ValueError("phase2a_materiality_approval_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_materiality_approval_input_must_be_object")
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


def _coverage_records(row: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    direct = row.get("candidate_coverage")
    if isinstance(direct, dict):
        return (direct,)
    records: list[dict[str, Any]] = []
    for component in row.get("component_evidence", []):
        if not isinstance(component, dict):
            raise ValueError("phase2a_materiality_approval_component_invalid")
        coverage = component.get("candidate_coverage")
        if isinstance(coverage, dict):
            records.append(coverage)
    return tuple(records)


def _validate_row(row: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    row_digest = _verify_seal(
        row,
        "row_content_sha256",
        "phase2a_materiality_approval_row_seal_invalid",
    )
    if (
        not str(row.get("row_id") or "")
        or int(row.get("component_count") or 0) != len(row.get("component_evidence") or [])
        or row.get("owner_materiality_decision") is not None
        or row.get("owner_comments") is not None
        or row.get("gold_change_authorized") is not False
        or row.get("source_admission_authorized") is not False
        or row.get("indexing_authorized") is not False
        or row.get("embedding_authorized") is not False
        or row.get("candidate_mutated") is not False
        or row.get("issue_technically_qualified") is not False
        or row.get("advisory_recommendation") not in EXPECTED_RECOMMENDATION_COUNTS
    ):
        raise ValueError("phase2a_materiality_approval_row_boundary_invalid")

    required = row.get("owner_source_admission_required") is True
    authorities = tuple(
        sorted(
            {
                str(coverage.get("authority_identity") or "")
                for coverage in _coverage_records(row)
                if coverage.get("owner_source_admission_required") is True
                and str(coverage.get("authority_identity") or "")
            }
        )
    )
    if required is not bool(authorities):
        raise ValueError("phase2a_materiality_approval_source_scope_invalid")
    return row_digest, authorities


def apply_approval(
    *,
    batch_path: Path,
    output_root: Path,
    owner_reply: str,
    recorded_at: datetime,
) -> dict[str, Any]:
    """Record one exact owner approval without advancing a later gate."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_materiality_approval_output_already_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_materiality_approval_output_mode_invalid")
    if recorded_at.tzinfo is None:
        raise ValueError("phase2a_materiality_approval_recorded_at_naive")
    if owner_reply != EXPECTED_OWNER_REPLY:
        raise ValueError("phase2a_materiality_approval_owner_reply_not_exact")

    batch = _load_object(batch_path)
    batch_digest = _verify_seal(
        batch,
        "artifact_content_sha256",
        "phase2a_materiality_approval_batch_seal_invalid",
    )
    rows = batch.get("rows")
    if (
        batch_digest != EXPECTED_BATCH_DIGEST
        or batch.get("schema") != BATCH_SCHEMA
        or batch.get("status") != "OWNER_ROW_MATERIALITY_DECISIONS_REQUIRED_NOT_APPLIED"
        or batch.get("row_count") != EXPECTED_ROW_COUNT
        or batch.get("recommendation_counts") != EXPECTED_RECOMMENDATION_COUNTS
        or batch.get("proposed_source_admission_authority_count")
        != EXPECTED_SOURCE_ADMISSION_AUTHORITY_COUNT
        or batch.get("owner_decision_required") is not True
        or batch.get("owner_decisions_applied") is not False
        or batch.get("automatic_gold_change") is not False
        or batch.get("automatic_source_admission") is not False
        or batch.get("automatic_indexing") is not False
        or batch.get("automatic_embedding") is not False
        or batch.get("candidate_mutated") is not False
        or batch.get("phase2b_authorized") is not False
        or batch.get("development30_authorized") is not False
        or not isinstance(rows, list)
        or len(rows) != EXPECTED_ROW_COUNT
    ):
        raise ValueError("phase2a_materiality_approval_batch_boundary_invalid")

    approved_rows: list[dict[str, Any]] = []
    source_rows: list[dict[str, Any]] = []
    rebind_rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    authorities: set[str] = set()
    recommendations: Counter[str] = Counter()
    for raw in rows:
        if not isinstance(raw, dict):
            raise ValueError("phase2a_materiality_approval_row_invalid")
        row = dict(raw)
        row_id = str(row.get("row_id") or "")
        if row_id in seen:
            raise ValueError("phase2a_materiality_approval_duplicate_row")
        seen.add(row_id)
        source_row_digest, row_authorities = _validate_row(row)
        authorities.update(row_authorities)
        recommendations[str(row["advisory_recommendation"])] += 1
        source_required = row["owner_source_admission_required"] is True
        approved_material = {
            **row,
            "source_row_content_sha256": source_row_digest,
            "status": "OWNER_APPROVED_INTERNAL_RESEARCH_TOOL_SCOPE",
            "owner_materiality_decision": "APPROVED_INTERNAL_PROPOSITION_MATERIALITY",
            "owner_source_admission_decision": (
                "APPROVED_PROPOSITION_LEVEL_SOURCE_ADMISSION"
                if source_required
                else "NOT_APPLICABLE_EXISTING_AUTHORITY"
            ),
            "source_admission_authorized": source_required,
            "gold_change_authorized": False,
            "indexing_authorized": False,
            "embedding_authorized": False,
            "candidate_mutated": False,
            "issue_technically_qualified": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        approved = {
            **approved_material,
            "approved_row_content_sha256": _sealed(approved_material),
        }
        approved_rows.append(approved)
        scope = {
            "row_id": row_id,
            "approved_row_content_sha256": approved["approved_row_content_sha256"],
            "official_source_title": row.get("official_source_title"),
            "official_citation": row.get("official_citation"),
            "stated_official_legal_locator": row.get("stated_official_legal_locator"),
            "component_evidence": row.get("component_evidence"),
            "currentness_evidence": row.get("currentness_evidence", []),
            "authority_identity_ids": list(row_authorities),
        }
        rebind_rows.append(scope)
        if source_required:
            source_rows.append(scope)

    expected_authorities = set(batch["proposed_source_admission_authorities"])
    if (
        recommendations != Counter(EXPECTED_RECOMMENDATION_COUNTS)
        or len(source_rows) != EXPECTED_SOURCE_ADMISSION_ROW_COUNT
        or len(authorities) != EXPECTED_SOURCE_ADMISSION_AUTHORITY_COUNT
        or authorities != expected_authorities
    ):
        raise ValueError("phase2a_materiality_approval_count_invariant_failed")

    approved_rows.sort(key=lambda item: str(item["row_id"]))
    source_rows.sort(key=lambda item: str(item["row_id"]))
    rebind_rows.sort(key=lambda item: str(item["row_id"]))
    recorded = recorded_at.astimezone(UTC).isoformat(timespec="seconds")
    owner_reply_sha256 = _sha256((owner_reply + "\n").encode("utf-8"))
    receipt_material = {
        "schema": "legalbot.v111.phase2a.materiality-owner-approval-receipt.v1",
        "status": "OWNER_APPROVED_54_MATERIALITY_AND_SOURCE_SCOPES_PHASE2A_ONLY",
        "owner_typed_name": "Agnes",
        "owner_decision_date": "2026-08-24",
        "owner_reply": owner_reply,
        "owner_reply_sha256": owner_reply_sha256,
        "recorded_at": recorded,
        "source_batch_content_sha256": batch_digest,
        "source_batch_file_sha256": _sha256_file(batch_path),
        "approved_row_count": len(approved_rows),
        "approved_source_admission_row_count": len(source_rows),
        "approved_source_admission_authority_count": len(authorities),
        "continued_phase2a_remediation_authorized": True,
        "candidate_build_deferred_until_one_consolidated_scope": True,
        "automatic_indexing_or_embedding_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "validation_promotion_or_live_authorized": False,
    }
    receipt = {**receipt_material, "receipt_content_sha256": _sealed(receipt_material)}

    package_material = {
        "schema": "legalbot.v111.phase2a.materiality-owner-approved-package.v1",
        "status": "OWNER_APPROVED_PHASE2A_MATERIALITY_AND_SOURCE_SCOPES",
        "owner_approval_receipt_content_sha256": receipt["receipt_content_sha256"],
        "row_count": len(approved_rows),
        "rows": approved_rows,
        "automatic_indexing_or_embedding_authorized": False,
        "candidate_build_deferred": True,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    package = {
        **package_material,
        "approved_package_content_sha256": _sealed(package_material),
    }

    source_material = {
        "schema": "legalbot.v111.phase2a.owner-approved-source-admission-scope.v1",
        "status": "OWNER_APPROVED_AWAITING_ONE_CONSOLIDATED_SUCCESSOR_MANIFEST",
        "source_owner_approved_package_content_sha256": package[
            "approved_package_content_sha256"
        ],
        "authority_count": len(authorities),
        "authority_identity_ids": sorted(authorities),
        "row_count": len(source_rows),
        "rows": source_rows,
        "automatic_indexing_or_embedding_authorized": False,
        "candidate_build_deferred": True,
    }
    source_scope = {
        **source_material,
        "artifact_content_sha256": _sealed(source_material),
    }

    rebind_material = {
        "schema": "legalbot.v111.phase2a.owner-approved-rebinding-scope.v1",
        "status": "OWNER_APPROVED_AWAITING_ONE_CONSOLIDATED_SUCCESSOR_DECISION",
        "source_owner_approved_package_content_sha256": package[
            "approved_package_content_sha256"
        ],
        "row_count": len(rebind_rows),
        "rows": rebind_rows,
        "sealed_predecessor_mutated": False,
        "candidate_build_deferred": True,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    rebind_scope = {
        **rebind_material,
        "artifact_content_sha256": _sealed(rebind_material),
    }

    progress_material = {
        "schema": "legalbot.v111.phase2a.progress-after-137-owner-decisions.v1",
        "status": "PHASE2A_REMEDIATION_CONTINUES",
        "canonical_issue_count": 585,
        "previous_recorded_owner_decision_count": 83,
        "new_owner_approved_materiality_scope_count": 54,
        "recorded_owner_decision_count": 137,
        "remaining_owner_decision_issue_count": 448,
        "technically_evidence_ready_owner_adopted_count": 48,
        "rebinding_or_successor_work_pending_count": 89,
        "all585_technical_qualification_passed": False,
        "common_currentness_cutoff_supportable": False,
        "automatic_indexing_or_embedding_authorized": False,
        "candidate_build_deferred": True,
        "phase2b_authorized": False,
        "development30_authorized": False,
        "terminal_verdict": (
            "PHASE 2A REMEDIATION CONTINUES — 137 OWNER DECISIONS RECORDED; "
            "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED"
        ),
    }
    progress = {
        **progress_material,
        "progress_content_sha256": _sealed(progress_material),
    }

    artifacts = {
        "OWNER-APPROVAL-RECEIPT-54.json": receipt,
        "OWNER-DECISIONS-APPROVED-54.json": package,
        "OWNER-APPROVED-SOURCE-ADMISSION-SCOPE-16.json": source_scope,
        "OWNER-APPROVED-CANDIDATE-REBINDING-SCOPE-54.json": rebind_scope,
        "PHASE2A-PROGRESS.json": progress,
    }
    for name, artifact in artifacts.items():
        _write_exclusive(output_root / name, _pretty_json(artifact))
    _write_exclusive(output_root / "OWNER-REPLY-EXACT.txt", (owner_reply + "\n").encode())
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
        "source_admission_scope_content_sha256": source_scope["artifact_content_sha256"],
        "candidate_rebinding_scope_content_sha256": rebind_scope["artifact_content_sha256"],
        "approved_row_count": len(approved_rows),
        "approved_source_admission_authority_count": len(authorities),
        "recorded_owner_decision_count": 137,
        "remaining_owner_decision_issue_count": 448,
        "candidate_build_deferred": True,
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
            "schema": "legalbot.v111.phase2a.materiality-owner-approval-failure.v1",
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
    parser.add_argument("--batch", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--owner-reply", required=True)
    parser.add_argument("--recorded-at", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        recorded_at = datetime.fromisoformat(str(args.recorded_at).replace("Z", "+00:00"))
        result = apply_approval(
            batch_path=args.batch.resolve(strict=True),
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
