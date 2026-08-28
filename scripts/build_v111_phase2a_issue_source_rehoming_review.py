#!/usr/bin/env python3
"""Verify quarantined UKSC spans and seal a non-admitting owner review batch."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

if __package__:
    from scripts import collect_v111_phase2a_issue_source_rehoming as rehoming
else:
    import collect_v111_phase2a_issue_source_rehoming as rehoming

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = PROJECT_ROOT / "config/phase2a_issue_source_rehoming_review.2026-08-25.v1.json"
DEFAULT_QUARANTINE_ROOT = (
    PROJECT_ROOT / "data/quarantine/2026-08-25/phase2a-issue-source-rehoming-r77"
)
DEFAULT_OUTPUT_ROOT = (
    PROJECT_ROOT / "data/evaluations/phase2a-owner-review/"
    "LegalBot-Phase2AB-2026-08-25-r86-issue-source-rehoming-review"
)
PLAN_SCHEMA = "legalbot.v111.phase2a.issue-source-rehoming-review-plan.v1"
EXPECTED_QUARANTINE_DIGEST = "83f9e4489d21e4a2dd58295e8b8365f892a1b7772d8d7e3a7582e765515187dd"
EXPECTED_PROPOSAL_COUNT = 5
EXPECTED_ORIGINAL_MAPPING_COUNT = 18
EXPECTED_SUPPORTED_CLAIM_COUNT = 6
EXPECTED_SUPPORTED_ROW_COUNT = 6
EXPECTED_REJECTED_MAPPING_COUNT = 13
_ROW_ID = re.compile(r"^live(?:30|60)-q\d{2}:issue-\d{2}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_rehoming_review_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_rehoming_review_input_must_be_object")
    return value


def _sealed(value: Any) -> str:
    return rehoming._sealed(value)


def _verify_seal(value: Mapping[str, Any], field: str, code: str) -> str:
    material = dict(value)
    supplied = str(material.pop(field, ""))
    if not _SHA256.fullmatch(supplied) or supplied != _sealed(material):
        raise ValueError(code)
    return supplied


def _write_json_exclusive(path: Path, value: Any) -> None:
    rehoming._write_exclusive(path, rehoming._pretty_json(value))


def _safe_member(root: Path, relative_path: str) -> Path:
    path = (PROJECT_ROOT / relative_path).resolve(strict=True)
    if path.is_symlink() or not path.is_file() or not path.is_relative_to(root):
        raise ValueError("phase2a_rehoming_review_member_invalid")
    return path


def _verify_checksums(root: Path) -> str:
    checksum_path = root / "SHA256SUMS.txt"
    if checksum_path.is_symlink() or not checksum_path.is_file():
        raise ValueError("phase2a_rehoming_review_checksums_missing")
    listed: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if separator != "  " or not _SHA256.fullmatch(digest) or not relative or relative in listed:
            raise ValueError("phase2a_rehoming_review_checksums_invalid")
        listed[relative] = digest
    actual_paths = {
        str(path.relative_to(root)): path
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS.txt"
    }
    if set(listed) != set(actual_paths):
        raise ValueError("phase2a_rehoming_review_checksum_inventory_invalid")
    for relative, path in actual_paths.items():
        if path.is_symlink() or rehoming._sha256_file(path) != listed[relative]:
            raise ValueError("phase2a_rehoming_review_checksum_mismatch")
    return rehoming._sha256_file(checksum_path)


def _validate_plan(plan: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    reviews = plan.get("reviews")
    if (
        plan.get("schema") != PLAN_SCHEMA
        or plan.get("as_of_date") != "2026-08-14"
        or plan.get("source_quarantine_artifact_content_sha256") != EXPECTED_QUARANTINE_DIGEST
        or plan.get("owner_proposition_level_admission_required") is not True
        or plan.get("automatic_source_admission") is not False
        or plan.get("automatic_gold_change") is not False
        or plan.get("automatic_indexing") is not False
        or plan.get("automatic_embedding") is not False
        or plan.get("candidate_mutation_authorized") is not False
        or plan.get("technical_qualification_assigned") is not False
        or plan.get("phase2b_authorized") is not False
        or plan.get("development30_authorized") is not False
        or not isinstance(reviews, list)
        or len(reviews) != EXPECTED_PROPOSAL_COUNT
    ):
        raise ValueError("phase2a_rehoming_review_plan_boundary_invalid")
    seen_reviews: set[str] = set()
    seen_claims: set[str] = set()
    result: list[dict[str, Any]] = []
    for raw in reviews:
        if not isinstance(raw, dict):
            raise ValueError("phase2a_rehoming_review_plan_item_invalid")
        review = dict(raw)
        proposal_id = str(review.get("proposal_id") or "")
        recommendation = str(review.get("source_recommendation") or "")
        claims = review.get("supported_claims")
        rejections = review.get("rejected_mappings")
        if (
            not proposal_id.startswith("issue-source-rehome-")
            or proposal_id in seen_reviews
            or not _SHA256.fullmatch(str(review.get("expected_record_content_sha256") or ""))
            or recommendation
            not in {
                "PROPOSE_PROPOSITION_LEVEL_ADMISSION_OWNER_DECISION_REQUIRED",
                "REJECT_SOURCE_FOR_PLANNED_BENCHMARK_ROWS",
            }
            or not str(review.get("later_treatment_status") or "")
            or not isinstance(claims, list)
            or not isinstance(rejections, list)
            or (recommendation.startswith("PROPOSE_") and not claims)
            or (recommendation.startswith("REJECT_") and claims)
        ):
            raise ValueError("phase2a_rehoming_review_plan_item_invalid")
        local_rows: set[str] = set()
        for claim in claims:
            if not isinstance(claim, Mapping):
                raise ValueError("phase2a_rehoming_review_claim_invalid")
            claim_id = str(claim.get("claim_id") or "")
            row_ids = claim.get("row_ids")
            exact = str(claim.get("exact_normalized_span_text") or "")
            if (
                not claim_id
                or claim_id in seen_claims
                or not isinstance(row_ids, list)
                or not row_ids
                or any(not isinstance(row, str) or not _ROW_ID.fullmatch(row) for row in row_ids)
                or len(set(row_ids)) != len(row_ids)
                or claim.get("binding_scope") not in {"DIRECT", "PARTIAL"}
                or not str(claim.get("proposition") or "")
                or not isinstance(claim.get("pdf_page_number"), int)
                or int(claim["pdf_page_number"]) < 1
                or not str(claim.get("paragraph_locator") or "")
                or not exact
                or exact != " ".join(exact.split())
            ):
                raise ValueError("phase2a_rehoming_review_claim_invalid")
            seen_claims.add(claim_id)
            local_rows.update(row_ids)
        for rejection in rejections:
            if (
                not isinstance(rejection, Mapping)
                or not _ROW_ID.fullmatch(str(rejection.get("row_id") or ""))
                or str(rejection["row_id"]) in local_rows
                or not str(rejection.get("reason_code") or "")
                or not str(rejection.get("rationale") or "")
            ):
                raise ValueError("phase2a_rehoming_review_rejection_invalid")
            local_rows.add(str(rejection["row_id"]))
        seen_reviews.add(proposal_id)
        result.append(review)
    return tuple(result)


def _load_verified_records(
    quarantine_root: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], str]:
    checksum_sha256 = _verify_checksums(quarantine_root)
    manifest_path = quarantine_root / "ISSUE-SOURCE-REHOMING-PROPOSALS-5.json"
    manifest = _load_object(manifest_path)
    manifest_digest = _verify_seal(
        manifest,
        "artifact_content_sha256",
        "phase2a_rehoming_review_quarantine_seal_invalid",
    )
    records = manifest.get("records")
    if (
        manifest_digest != EXPECTED_QUARANTINE_DIGEST
        or manifest.get("record_count") != EXPECTED_PROPOSAL_COUNT
        or manifest.get("affected_row_count") != EXPECTED_ORIGINAL_MAPPING_COUNT
        or manifest.get("source_admission_authorized") is not False
        or manifest.get("candidate_mutated") is not False
        or manifest.get("phase2b_authorized") is not False
        or not isinstance(records, list)
    ):
        raise ValueError("phase2a_rehoming_review_quarantine_boundary_invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for raw in records:
        if not isinstance(raw, dict):
            raise ValueError("phase2a_rehoming_review_record_invalid")
        record = dict(raw)
        record_digest = _verify_seal(
            record,
            "record_content_sha256",
            "phase2a_rehoming_review_record_seal_invalid",
        )
        proposal_id = str(record.get("proposal_id") or "")
        if proposal_id in by_id or record.get("source_admitted") is not False:
            raise ValueError("phase2a_rehoming_review_record_invalid")
        pdf_path = _safe_member(
            quarantine_root, str(record["official_judgment_pdf"]["relative_path"])
        )
        pages_path = _safe_member(
            quarantine_root, str(record["derived_page_text"]["relative_path"])
        )
        if (
            rehoming._sha256_file(pdf_path) != record["official_judgment_pdf"]["sha256"]
            or pdf_path.stat().st_size != record["official_judgment_pdf"]["bytes"]
            or rehoming._sha256_file(pages_path) != record["derived_page_text"]["sha256"]
        ):
            raise ValueError("phase2a_rehoming_review_source_hash_mismatch")
        pages = _load_object(pages_path)
        page_values = pages.get("pages")
        if (
            pages.get("schema") != "legalbot.v111.phase2a.derived-uksc-page-text.v1"
            or pages.get("source_pdf_sha256") != record["official_judgment_pdf"]["sha256"]
            or pages.get("page_count") != record["official_judgment_pdf"]["page_count"]
            or not isinstance(page_values, list)
            or len(page_values) != pages.get("page_count")
        ):
            raise ValueError("phase2a_rehoming_review_derived_pages_invalid")
        for page in page_values:
            if not isinstance(page, Mapping) or rehoming._sha256(
                str(page.get("text") or "").encode()
            ) != page.get("text_sha256"):
                raise ValueError("phase2a_rehoming_review_derived_page_hash_invalid")
        by_id[proposal_id] = {
            "record": record,
            "record_content_sha256": record_digest,
            "pages": {int(page["page_number"]): dict(page) for page in page_values},
        }
    return manifest, by_id, checksum_sha256


def build(*, plan_path: Path, quarantine_root: Path, output_root: Path) -> dict[str, Any]:
    """Create an immutable owner-review batch without admitting any source."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_rehoming_review_output_exists")
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_rehoming_review_output_mode_invalid")
    plan = _load_object(plan_path)
    reviews = _validate_plan(plan)
    manifest, records, checksum_sha256 = _load_verified_records(quarantine_root)
    if set(records) != {str(review["proposal_id"]) for review in reviews}:
        raise ValueError("phase2a_rehoming_review_inventory_mismatch")
    global_original_rows = {
        str(row) for value in records.values() for row in value["record"]["affected_rows"]
    }

    source_reviews: list[dict[str, Any]] = []
    supported_rows: set[str] = set()
    original_supported_pairs: set[tuple[str, str]] = set()
    rejected_pairs: set[tuple[str, str]] = set()
    exact_claim_count = 0
    for review in reviews:
        proposal_id = str(review["proposal_id"])
        source = records[proposal_id]
        record = source["record"]
        if source["record_content_sha256"] != review["expected_record_content_sha256"]:
            raise ValueError("phase2a_rehoming_review_expected_record_digest_mismatch")
        original_rows = set(str(row) for row in record["affected_rows"])
        claim_bindings: list[dict[str, Any]] = []
        locally_supported: set[str] = set()
        for claim in review["supported_claims"]:
            page_number = int(claim["pdf_page_number"])
            page = source["pages"].get(page_number)
            if page is None:
                raise ValueError("phase2a_rehoming_review_claim_page_missing")
            exact_text = str(claim["exact_normalized_span_text"])
            page_text = str(page["text"])
            if page_text.count(exact_text) != 1:
                raise ValueError(
                    f"phase2a_rehoming_review_exact_span_not_unique:{claim['claim_id']}"
                )
            start = page_text.index(exact_text)
            row_ids = [str(row) for row in claim["row_ids"]]
            if any(row not in global_original_rows for row in row_ids):
                raise ValueError("phase2a_rehoming_review_claim_row_outside_inventory")
            material = {
                "claim_id": claim["claim_id"],
                "row_ids": row_ids,
                "issue_label": claim["issue_label"],
                "binding_scope": claim["binding_scope"],
                "proposition": claim["proposition"],
                "neutral_citation": record["neutral_citation"],
                "case_name": record["case_name"],
                "official_judgment_pdf_url": record["official_judgment_pdf"]["url"],
                "official_judgment_pdf_sha256": record["official_judgment_pdf"]["sha256"],
                "pdf_page_number": page_number,
                "printed_page_label": claim["printed_page_label"],
                "paragraph_locator": claim["paragraph_locator"],
                "parent_page_text_sha256": page["text_sha256"],
                "exact_normalized_span_text": exact_text,
                "exact_normalized_span_sha256": rehoming._sha256(exact_text.encode()),
                "start_character": start,
                "end_character_exclusive": start + len(exact_text),
                "span_truncated": False,
                "owner_materiality_decision": None,
            }
            claim_bindings.append({**material, "binding_content_sha256": _sealed(material)})
            exact_claim_count += 1
            supported_rows.update(row_ids)
            locally_supported.update(row_ids)
            original_supported_pairs.update(
                (proposal_id, row) for row in row_ids if row in original_rows
            )
        rejection_values: list[dict[str, Any]] = []
        for rejection in review["rejected_mappings"]:
            row_id = str(rejection["row_id"])
            if row_id not in original_rows:
                raise ValueError("phase2a_rehoming_review_rejection_not_original_mapping")
            material = {
                **rejection,
                "neutral_citation": record["neutral_citation"],
                "owner_mapping_decision": None,
            }
            rejection_values.append({**material, "rejection_content_sha256": _sealed(material)})
            rejected_pairs.add((proposal_id, row_id))
        if {(proposal_id, row) for row in original_rows} != original_supported_pairs.intersection(
            {(proposal_id, row) for row in original_rows}
        ).union(rejected_pairs.intersection({(proposal_id, row) for row in original_rows})):
            raise ValueError("phase2a_rehoming_review_original_mapping_coverage_invalid")
        source_material = {
            "proposal_id": proposal_id,
            "case_id": record["case_id"],
            "case_name": record["case_name"],
            "neutral_citation": record["neutral_citation"],
            "judgment_date": record["judgment_date"],
            "source_date": record["source_date"],
            "official_case_page": record["official_case_page"],
            "official_judgment_pdf": record["official_judgment_pdf"],
            "record_content_sha256": source["record_content_sha256"],
            "original_affected_rows": sorted(original_rows),
            "source_recommendation": review["source_recommendation"],
            "later_treatment_status": review["later_treatment_status"],
            "supported_claims": claim_bindings,
            "rejected_mappings": rejection_values,
            "owner_source_admission_decision": None,
            "source_admitted": False,
            "indexed": False,
            "embedded": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
        }
        source_reviews.append(
            {**source_material, "source_review_content_sha256": _sealed(source_material)}
        )

    original_pairs = {
        (proposal_id, str(row))
        for proposal_id, value in records.items()
        for row in value["record"]["affected_rows"]
    }
    if (
        len(original_pairs) != EXPECTED_ORIGINAL_MAPPING_COUNT
        or original_supported_pairs.union(rejected_pairs) != original_pairs
        or len(rejected_pairs) != EXPECTED_REJECTED_MAPPING_COUNT
        or exact_claim_count != EXPECTED_SUPPORTED_CLAIM_COUNT
        or len(supported_rows) != EXPECTED_SUPPORTED_ROW_COUNT
    ):
        raise ValueError("phase2a_rehoming_review_expected_counts_invalid")

    verification_material = {
        "schema": "legalbot.v111.phase2a.issue-source-rehoming-verification.v1",
        "status": "EXACT_UKSC_SOURCE_ROW_REVIEW_VERIFIED_OWNER_DECISION_REQUIRED",
        "source_quarantine_artifact_content_sha256": manifest["artifact_content_sha256"],
        "source_quarantine_checksum_file_sha256": checksum_sha256,
        "review_plan_file_sha256": rehoming._sha256_file(plan_path),
        "review_plan_content_sha256": _sealed(plan),
        "source_count": len(source_reviews),
        "proposed_source_admission_count": sum(
            row["source_recommendation"].startswith("PROPOSE_") for row in source_reviews
        ),
        "rejected_source_count": sum(
            row["source_recommendation"].startswith("REJECT_") for row in source_reviews
        ),
        "original_source_row_mapping_count": len(original_pairs),
        "original_supported_mapping_count": len(original_supported_pairs),
        "corrective_remapped_supported_mapping_count": sum(
            row not in set(records[proposal_id]["record"]["affected_rows"])
            for proposal_id, review in ((str(item["proposal_id"]), item) for item in reviews)
            for claim in review["supported_claims"]
            for row in claim["row_ids"]
        ),
        "rejected_mapping_count": len(rejected_pairs),
        "supported_claim_count": exact_claim_count,
        "supported_row_count": len(supported_rows),
        "all_exact_spans_unique": True,
        "all_source_hashes_match": True,
        "all_original_mappings_disposed": True,
        "later_treatment_still_required_before_final_qualification": True,
        "owner_decision_required": True,
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    verification = {
        **verification_material,
        "artifact_content_sha256": _sealed(verification_material),
    }
    batch_material = {
        "schema": "legalbot.v111.phase2a.issue-source-rehoming-owner-batch.v1",
        "status": "OWNER_PROPOSITION_AND_SOURCE_ADMISSION_DECISION_REQUIRED",
        "verification_content_sha256": verification["artifact_content_sha256"],
        "source_reviews": source_reviews,
        "owner_decision_required": True,
        "source_admission_authorized": False,
        "automatic_gold_change": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    batch = {**batch_material, "artifact_content_sha256": _sealed(batch_material)}
    _write_json_exclusive(output_root / "ISSUE-SOURCE-REHOMING-VERIFICATION.json", verification)
    _write_json_exclusive(output_root / "OWNER-ISSUE-SOURCE-ADMISSION-BATCH.json", batch)
    package_material = {
        "schema": "legalbot.v111.phase2a.issue-source-rehoming-review-package.v1",
        "status": verification["status"],
        "verification_content_sha256": verification["artifact_content_sha256"],
        "owner_batch_content_sha256": batch["artifact_content_sha256"],
        "source_admission_authorized": False,
        "candidate_mutated": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    package = {**package_material, "package_content_sha256": _sealed(package_material)}
    _write_json_exclusive(output_root / "PACKAGE-MANIFEST.json", package)
    rehoming._write_exclusive(
        output_root / "OUTCOME.txt",
        (
            "PHASE 2A UKSC SOURCE REVIEW READY — EXACT SPANS VERIFIED; UNRELATED "
            "MAPPINGS REJECTED; OWNER MATERIALITY AND SOURCE ADMISSION DECISIONS "
            "REQUIRED; NO INDEX OR CANDIDATE CHANGE; PHASE 2B NOT AUTHORIZED\n"
        ).encode(),
    )
    return {
        "output_root": str(output_root),
        "status": verification["status"],
        "owner_batch_content_sha256": batch["artifact_content_sha256"],
        "package_content_sha256": package["package_content_sha256"],
        "proposed_source_admission_count": verification["proposed_source_admission_count"],
        "supported_row_count": len(supported_rows),
        "rejected_mapping_count": len(rejected_pairs),
        "source_admission_authorized": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }


def _persist_failure(output_root: Path, exc: BaseException) -> None:
    try:
        output_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = output_root / "FAILURE.json"
        if path.exists():
            return
        fingerprint = rehoming._sha256(f"{type(exc).__name__}:{exc}".encode())
        material = {
            "schema": "legalbot.v111.phase2a.issue-source-rehoming-review-failure.v1",
            "status": "FAILED_DIAGNOSTICS_PERSISTED_BEFORE_EXIT",
            "failure_type": type(exc).__name__,
            "failure_message": str(exc),
            "failure_fingerprint": fingerprint,
            "affected_stage": "PHASE2A_UKSC_PROPOSITION_REVIEW",
            "root_cause_status": "REQUIRES_DEBUG_BEFORE_RETRY",
            "source_admission_authorized": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        _write_json_exclusive(path, {**material, "failure_content_sha256": _sealed(material)})
    except Exception:
        return


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--quarantine-root", type=Path, default=DEFAULT_QUARANTINE_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args(argv)
    output_root = args.output_root.resolve()
    try:
        result = build(
            plan_path=args.plan.resolve(strict=True),
            quarantine_root=args.quarantine_root.resolve(strict=True),
            output_root=output_root,
        )
    except Exception as exc:
        _persist_failure(output_root, exc)
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
