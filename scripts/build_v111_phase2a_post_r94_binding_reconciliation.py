#!/usr/bin/env python3
"""Reconcile r94-approved bindings against the 364 carried Phase-2A gaps.

The r95 receipt deliberately carried every pre-approval gap forward unchanged.
This create-only pass now distinguishes:

* three target-date legislation rows whose direct proposition, exact span and
  currentness/transition evidence were all approved;
* three direct UKSC bindings that still require later-treatment review;
* two partial bindings that still require additional proposition evidence; and
* the remaining rows that have no r94-approved binding.

It does not qualify a row, mutate or build a candidate, index or embed a source,
or authorize Phase 2B/Development 30.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"
DEFAULT_R95_ROOT = REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-25-r95-substantive-owner-approved"
DEFAULT_R83_BATCH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r83-supplemental-proposition-verification"
    / "OWNER-SOURCE-ADMISSION-BATCH.json"
)
DEFAULT_R84_BATCH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r84-procurement-currentness-verification"
    / "OWNER-SOURCE-ADMISSION-BATCH.json"
)
DEFAULT_R85_BATCH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r85-as-made-currentness-verification"
    / "OWNER-SOURCE-ADMISSION-BATCH.json"
)
DEFAULT_R86_BATCH = (
    REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r86-issue-source-rehoming-review"
    / "OWNER-ISSUE-SOURCE-ADMISSION-BATCH.json"
)
DEFAULT_OUTPUT_ROOT = (
    REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-26-r96-approved-binding-reconciliation"
)

EXPECTED_R95_PACKAGE_DIGEST = "a2df2408785defdefa9622fb7e6df33be3306b2e8d4053b9015ef49a80091f53"
EXPECTED_R95_GAPS_DIGEST = "513c58f6eac13d9c51c99efe657d7809158392687143edd67a6b9832e4ecbb34"
EXPECTED_R95_SUPPLEMENTAL_DIGEST = (
    "e29d8af0463d19ec7ff83640d796af90b4c460e193b17fa69293341ac19edddd"
)
EXPECTED_R95_UKSC_DIGEST = "3fb57743fa655344de0c233320d042a5e4428f28f6034500920d5f3fedabffc5"
EXPECTED_SOURCE_BATCH_DIGESTS = frozenset(
    {
        "5410b7888ac72224a0828d43d0ddbc36768a636ea54ecb1687e576958108b28d",
        "1f33e04ef9ea7d39c15fba16bd2c10b1f5e7e40af008eb3180fc4d37ca03a10f",
        "0ead28488b0fa6fc8c18cdfe532092b0ce397613361426b1991cbfe66ceb9fb6",
    }
)
EXPECTED_R86_DIGEST = "623836f3882d6c921920adb8af32bb8bd9cf3836bfb9ed20cdd4095fc627d9b3"

EXPECTED_TARGET_DATE_READY_ROWS = frozenset(
    {
        "live30-q21:issue-06",
        "live30-q21:issue-08",
        "live30-q23:issue-03",
    }
)
EXPECTED_UKSC_CURRENTNESS_PENDING_ROWS = frozenset(
    {
        "live30-q18:issue-05",
        "live30-q20:issue-02",
        "live60-q43:issue-06",
    }
)
EXPECTED_PARTIAL_ROWS = frozenset(
    {
        "live30-q21:issue-07",
        "live30-q27:issue-08",
    }
)
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
        raise ValueError("phase2a_post_r94_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_post_r94_input_must_be_object")
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


def _records(value: Mapping[str, Any], *, expected: int, code: str) -> list[dict[str, Any]]:
    records = value.get("records")
    if (
        value.get("record_count") != expected
        or not isinstance(records, list)
        or len(records) != expected
        or any(not isinstance(item, dict) for item in records)
    ):
        raise ValueError(code)
    return [dict(item) for item in records]


def _verify_r95(
    root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    package = _load_object(root / "PACKAGE-INDEX.json")
    _verify_seal(
        package,
        "package_content_sha256",
        "phase2a_post_r94_package_seal_invalid",
        EXPECTED_R95_PACKAGE_DIGEST,
    )
    if (
        package.get("remaining_material_gap_count") != 364
        or package.get("approved_source_admission_count") != 20
        or package.get("automatic_indexing") is not False
        or package.get("automatic_embedding") is not False
        or package.get("candidate_mutated") is not False
        or package.get("phase2b_authorized") is not False
        or package.get("development30_authorized") is not False
    ):
        raise ValueError("phase2a_post_r94_package_boundary_invalid")

    expected_files = package.get("files")
    if not isinstance(expected_files, dict):
        raise ValueError("phase2a_post_r94_file_inventory_invalid")
    for filename in (
        "REMAINING-MATERIAL-GAPS-364.json",
        "APPROVED-SUPPLEMENTAL-BINDINGS-13.json",
        "APPROVED-UKSC-SOURCE-REVIEWS-5.json",
    ):
        entry = expected_files.get(filename)
        path = root / filename
        if not isinstance(entry, dict) or entry.get("sha256") != _sha256_file(path):
            raise ValueError("phase2a_post_r94_file_inventory_invalid")

    gaps = _load_object(root / "REMAINING-MATERIAL-GAPS-364.json")
    _verify_seal(
        gaps,
        "artifact_content_sha256",
        "phase2a_post_r94_gap_seal_invalid",
        EXPECTED_R95_GAPS_DIGEST,
    )
    supplemental = _load_object(root / "APPROVED-SUPPLEMENTAL-BINDINGS-13.json")
    _verify_seal(
        supplemental,
        "artifact_content_sha256",
        "phase2a_post_r94_supplemental_seal_invalid",
        EXPECTED_R95_SUPPLEMENTAL_DIGEST,
    )
    uksc = _load_object(root / "APPROVED-UKSC-SOURCE-REVIEWS-5.json")
    _verify_seal(
        uksc,
        "artifact_content_sha256",
        "phase2a_post_r94_uksc_seal_invalid",
        EXPECTED_R95_UKSC_DIGEST,
    )
    return (
        _records(gaps, expected=364, code="phase2a_post_r94_gap_inventory_invalid"),
        _records(
            supplemental,
            expected=13,
            code="phase2a_post_r94_supplemental_inventory_invalid",
        ),
        _records(uksc, expected=5, code="phase2a_post_r94_uksc_inventory_invalid"),
    )


def _verify_source_batches(paths: Sequence[Path]) -> dict[str, dict[str, Any]]:
    if len(paths) != 3:
        raise ValueError("phase2a_post_r94_source_batch_count_invalid")
    proposals: dict[str, dict[str, Any]] = {}
    observed_digests: set[str] = set()
    for path in paths:
        batch = _load_object(path)
        observed_digests.add(
            _verify_seal(
                batch,
                "artifact_content_sha256",
                "phase2a_post_r94_source_batch_seal_invalid",
            )
        )
        values = batch.get("proposals")
        if (
            batch.get("owner_decision_required") is not True
            or batch.get("automatic_source_admission") is not False
            or batch.get("automatic_indexing") is not False
            or batch.get("automatic_embedding") is not False
            or batch.get("candidate_mutated") is not False
            or batch.get("phase2b_authorized") is not False
            or batch.get("development30_authorized") is not False
            or not isinstance(values, list)
        ):
            raise ValueError("phase2a_post_r94_source_batch_boundary_invalid")
        for item in values:
            if not isinstance(item, dict):
                raise ValueError("phase2a_post_r94_source_proposal_invalid")
            digest = str(item.get("proposal_content_sha256") or "")
            if not _SHA256.fullmatch(digest) or digest != _sealed(
                {key: value for key, value in item.items() if key != "proposal_content_sha256"}
            ):
                raise ValueError("phase2a_post_r94_source_proposal_seal_invalid")
            if digest in proposals:
                raise ValueError("phase2a_post_r94_source_proposal_duplicate")
            proposals[digest] = dict(item)
    if observed_digests != EXPECTED_SOURCE_BATCH_DIGESTS:
        raise ValueError("phase2a_post_r94_source_batch_identity_invalid")
    return proposals


def _verify_r86(path: Path) -> dict[str, dict[str, Any]]:
    batch = _load_object(path)
    _verify_seal(
        batch,
        "artifact_content_sha256",
        "phase2a_post_r94_r86_seal_invalid",
        EXPECTED_R86_DIGEST,
    )
    reviews = batch.get("source_reviews")
    if (
        batch.get("source_admission_authorized") is not False
        or batch.get("candidate_mutated") is not False
        or not isinstance(reviews, list)
        or len(reviews) != 5
    ):
        raise ValueError("phase2a_post_r94_r86_boundary_invalid")
    by_digest: dict[str, dict[str, Any]] = {}
    for review in reviews:
        if not isinstance(review, dict):
            raise ValueError("phase2a_post_r94_r86_review_invalid")
        digest = str(review.get("source_review_content_sha256") or "")
        if not _SHA256.fullmatch(digest):
            raise ValueError("phase2a_post_r94_r86_review_invalid")
        by_digest[digest] = dict(review)
    if len(by_digest) != 5:
        raise ValueError("phase2a_post_r94_r86_review_duplicate")
    return by_digest


def _reconcile(
    *,
    gaps: Sequence[Mapping[str, Any]],
    approved_supplemental: Sequence[Mapping[str, Any]],
    approved_uksc: Sequence[Mapping[str, Any]],
    source_proposals: Mapping[str, Mapping[str, Any]],
    uksc_reviews: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    gap_by_id = {str(item.get("row_id") or ""): dict(item) for item in gaps}
    if len(gap_by_id) != 364 or "" in gap_by_id:
        raise ValueError("phase2a_post_r94_gap_row_ids_invalid")

    direct: dict[str, dict[str, Any]] = {}
    partial: dict[str, dict[str, Any]] = {}
    supplemental_currentness: dict[str, list[dict[str, Any]]] = {}
    for approved in approved_supplemental:
        source_decision = approved.get("source_decision")
        if not isinstance(source_decision, dict):
            raise ValueError("phase2a_post_r94_approved_supplemental_invalid")
        proposal_digest = str(source_decision.get("proposal_content_sha256") or "")
        proposal = source_proposals.get(proposal_digest)
        if proposal is None:
            raise ValueError("phase2a_post_r94_approved_supplemental_source_missing")
        if (
            source_decision.get("binding_id") != proposal.get("binding_id")
            or source_decision.get("binding_scope") != proposal.get("binding_scope")
            or source_decision.get("row_ids") != proposal.get("row_ids")
        ):
            raise ValueError("phase2a_post_r94_approved_supplemental_mismatch")
        for row_id in proposal["row_ids"]:
            if row_id not in gap_by_id:
                continue
            binding = {
                "binding_origin": "R94_APPROVED_SUPPLEMENTAL_OFFICIAL_SOURCE",
                "binding_id": proposal["binding_id"],
                "binding_scope": proposal["binding_scope"],
                "authority_identity": proposal["authority_identity"],
                "source_target_id": proposal["source_target_id"],
                "official_url": proposal["official_url"],
                "official_file_sha256": proposal["official_file_sha256"],
                "material_claim_spans": proposal["material_claim_spans"],
                "currentness_spans": proposal["currentness_spans"],
                "source_proposal_content_sha256": proposal_digest,
                "owner_approval_bound_to_r94": True,
                "technical_qualification_assigned": False,
            }
            if proposal["binding_scope"] not in {"DIRECT", "PARTIAL"}:
                supplemental_currentness.setdefault(row_id, []).append(binding)
                continue
            target = direct if proposal["binding_scope"] == "DIRECT" else partial
            record = target.setdefault(
                row_id,
                {
                    "row_id": row_id,
                    "bindings": [],
                    "owner_approval_bound_to_r94": True,
                    "technical_qualification_assigned": False,
                },
            )
            record["bindings"].append(binding)

    approved_review_digests = {
        str(item.get("source_decision", {}).get("source_review_content_sha256") or "")
        for item in approved_uksc
        if isinstance(item.get("source_decision"), dict)
        and item.get("owner_outcome") == "APPROVE_PROPOSITION_BINDINGS_AND_SOURCE_ADMISSION"
    }
    for digest in approved_review_digests:
        review = uksc_reviews.get(digest)
        if review is None:
            raise ValueError("phase2a_post_r94_approved_uksc_source_missing")
        for claim in review.get("supported_claims", []):
            if not isinstance(claim, dict):
                raise ValueError("phase2a_post_r94_uksc_claim_invalid")
            for row_id in claim.get("row_ids", []):
                if row_id not in gap_by_id:
                    continue
                binding = {
                    "binding_origin": "R94_APPROVED_UKSC_OFFICIAL_JUDGMENT",
                    "binding_id": claim["claim_id"],
                    "binding_scope": claim["binding_scope"],
                    "authority_identity": review["neutral_citation"],
                    "case_name": review["case_name"],
                    "official_url": claim["official_judgment_pdf_url"],
                    "official_file_sha256": claim["official_judgment_pdf_sha256"],
                    "proposition": claim["proposition"],
                    "exact_normalized_span_text": claim["exact_normalized_span_text"],
                    "exact_normalized_span_sha256": claim["exact_normalized_span_sha256"],
                    "paragraph_locator": claim["paragraph_locator"],
                    "source_review_content_sha256": digest,
                    "later_treatment_review_required": True,
                    "owner_approval_bound_to_r94": True,
                    "technical_qualification_assigned": False,
                }
                target = direct if claim["binding_scope"] == "DIRECT" else partial
                record = target.setdefault(
                    row_id,
                    {
                        "row_id": row_id,
                        "bindings": [],
                        "owner_approval_bound_to_r94": True,
                        "technical_qualification_assigned": False,
                    },
                )
                record["bindings"].append(binding)

    for row_id, bindings in supplemental_currentness.items():
        target_record = direct.get(row_id) or partial.get(row_id)
        if target_record is not None:
            target_record["currentness_and_transition_bindings"] = bindings

    observed = frozenset(direct) | frozenset(partial)
    expected = (
        EXPECTED_TARGET_DATE_READY_ROWS
        | EXPECTED_UKSC_CURRENTNESS_PENDING_ROWS
        | EXPECTED_PARTIAL_ROWS
    )
    if (
        observed != expected
        or frozenset(direct)
        != (EXPECTED_TARGET_DATE_READY_ROWS | EXPECTED_UKSC_CURRENTNESS_PENDING_ROWS)
        or frozenset(partial) != EXPECTED_PARTIAL_ROWS
    ):
        raise ValueError("phase2a_post_r94_binding_row_inventory_invalid")

    resolved: list[dict[str, Any]] = []
    retained: list[dict[str, Any]] = []
    for row_id in sorted(direct):
        record = direct[row_id]
        if row_id in EXPECTED_TARGET_DATE_READY_ROWS:
            resolved.append(
                {
                    **record,
                    "reconciliation_status": (
                        "OWNER_APPROVED_DIRECT_TARGET_DATE_EVIDENCE_READY_FOR_FINAL_QUALIFICATION"
                    ),
                    "remaining_dependency": None,
                }
            )
        else:
            retained.append(
                {
                    **record,
                    "reconciliation_status": (
                        "OWNER_APPROVED_DIRECT_BINDING_LATER_TREATMENT_REVIEW_REQUIRED"
                    ),
                    "remaining_dependency": "JUDGMENT_LATER_TREATMENT_CURRENTNESS_REVIEW",
                }
            )
    for row_id in sorted(partial):
        retained.append(
            {
                **partial[row_id],
                "reconciliation_status": "OWNER_APPROVED_PARTIAL_BINDING_MORE_EVIDENCE_REQUIRED",
                "remaining_dependency": "ADDITIONAL_DIRECT_PROPOSITION_EVIDENCE",
            }
        )

    resolved_ids = {item["row_id"] for item in resolved}
    remaining: list[dict[str, Any]] = []
    retained_by_id = {item["row_id"]: item for item in retained}
    for row_id, original in sorted(gap_by_id.items()):
        if row_id in resolved_ids:
            continue
        carry = retained_by_id.get(row_id)
        remaining.append(
            {
                **original,
                "post_r94_reconciliation_status": (
                    carry["reconciliation_status"]
                    if carry
                    else "NO_R94_APPROVED_DIRECT_BINDING_RESEARCH_REMAINS_REQUIRED"
                ),
                "remaining_dependency": (
                    carry["remaining_dependency"]
                    if carry
                    else "OFFICIAL_SOURCE_OR_GOLD_DEFINITION_REMEDIATION"
                ),
                "technical_qualification_assigned": False,
            }
        )
    if len(resolved) != 3 or len(retained) != 5 or len(remaining) != 361:
        raise ValueError("phase2a_post_r94_reconciliation_count_invalid")
    return resolved, retained, remaining


def build_reconciliation(
    *,
    r95_root: Path,
    source_batch_paths: Sequence[Path],
    r86_batch_path: Path,
    output_root: Path,
) -> dict[str, Any]:
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_post_r94_output_already_exists")
    gaps, supplemental, uksc = _verify_r95(r95_root)
    proposals = _verify_source_batches(source_batch_paths)
    reviews = _verify_r86(r86_batch_path)
    resolved, retained, remaining = _reconcile(
        gaps=gaps,
        approved_supplemental=supplemental,
        approved_uksc=uksc,
        source_proposals=proposals,
        uksc_reviews=reviews,
    )

    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_post_r94_output_mode_invalid")
    artifacts = {
        "TARGET-DATE-EVIDENCE-READY-ROWS-3.json": _sealed_artifact(
            "legalbot.v111.phase2a.post-r94-target-date-ready-rows.v1",
            {
                "status": "OWNER_APPROVED_BINDINGS_READY_FOR_FINAL_PHASE2A_QUALIFICATION",
                "record_count": 3,
                "records": resolved,
                "owner_decisions_applied": True,
                "technical_qualification_assigned": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
        ),
        "RETAINED-DIRECT-OR-PARTIAL-GAPS-5.json": _sealed_artifact(
            "legalbot.v111.phase2a.post-r94-retained-binding-gaps.v1",
            {
                "status": "APPROVED_BINDINGS_RETAINED_FOR_CURRENTNESS_OR_MORE_EVIDENCE",
                "record_count": 5,
                "records": retained,
                "owner_decisions_applied": True,
                "technical_qualification_assigned": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
        ),
        "REMAINING-PHASE2A-RESEARCH-ROWS-361.json": _sealed_artifact(
            "legalbot.v111.phase2a.post-r94-remaining-research-rows.v1",
            {
                "status": "PHASE2A_OFFICIAL_SOURCE_RESEARCH_REMAINS_REQUIRED",
                "record_count": 361,
                "records": remaining,
                "owner_decisions_applied": False,
                "technical_qualification_assigned": False,
                "source_admission_authorized": False,
                "automatic_indexing": False,
                "automatic_embedding": False,
                "candidate_mutated": False,
                "phase2b_authorized": False,
                "development30_authorized": False,
            },
        ),
    }
    for filename, artifact in artifacts.items():
        _write_exclusive(output_root / filename, _pretty_json(artifact))
    _write_exclusive(
        output_root / "OUTCOME.txt",
        (
            "PHASE 2A R94 BINDING RECONCILIATION COMPLETE — 3 TARGET-DATE ROWS "
            "EVIDENCE-READY; 361 RESEARCH ROWS REMAIN; NO PHASE 2B\n"
        ).encode(),
    )
    files = sorted(path for path in output_root.iterdir() if path.is_file())
    package_material = {
        "schema": "legalbot.v111.phase2a.post-r94-binding-reconciliation-package.v1",
        "status": "R94_BINDINGS_RECONCILED_361_PHASE2A_RESEARCH_ROWS_REMAIN",
        "source_r95_package_content_sha256": EXPECTED_R95_PACKAGE_DIGEST,
        "target_date_evidence_ready_count": 3,
        "retained_binding_gap_count": 5,
        "remaining_research_row_count": 361,
        "files": {
            path.name: {"bytes": path.stat().st_size, "sha256": _sha256_file(path)}
            for path in files
        },
        "owner_decisions_applied": True,
        "technical_qualification_assigned": False,
        "source_admission_authorized_beyond_r94": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    package = {
        **package_material,
        "package_content_sha256": _sealed(package_material),
    }
    _write_exclusive(output_root / "PACKAGE-INDEX.json", _pretty_json(package))
    checksum_files = sorted(
        path for path in output_root.iterdir() if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    _write_exclusive(
        output_root / "SHA256SUMS.txt",
        "".join(f"{_sha256_file(path)}  {path.name}\n" for path in checksum_files).encode(),
    )
    return package


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--r95-root", type=Path, default=DEFAULT_R95_ROOT)
    parser.add_argument("--r83-batch", type=Path, default=DEFAULT_R83_BATCH)
    parser.add_argument("--r84-batch", type=Path, default=DEFAULT_R84_BATCH)
    parser.add_argument("--r85-batch", type=Path, default=DEFAULT_R85_BATCH)
    parser.add_argument("--r86-batch", type=Path, default=DEFAULT_R86_BATCH)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    result = build_reconciliation(
        r95_root=args.r95_root.resolve(strict=True),
        source_batch_paths=(
            args.r83_batch.resolve(strict=True),
            args.r84_batch.resolve(strict=True),
            args.r85_batch.resolve(strict=True),
        ),
        r86_batch_path=args.r86_batch.resolve(strict=True),
        output_root=args.output_root.resolve(),
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
