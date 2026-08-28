#!/usr/bin/env python3
"""Build a non-authorising cross-subject seminar authority priority queue."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "config/seminar_gap_official_uk_judgments_round2.2026-08-26.v1.json"
)
DEFAULT_AUDIT = PROJECT_ROOT / "data/reports/seminar-authority-coverage-2026-08-26-v5.json"
DEFAULT_VERIFICATION = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-uk-judgments-round2-2026-08-26-verification.json"
)
DEFAULT_LEGISLATION_RESOLUTION = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-legislation-title-resolution-2026-08-26.json"
)
DEFAULT_LEGISLATION_VERIFICATION = (
    PROJECT_ROOT
    / "data/review_queue/seminar-gap-official-legislation-round2-2026-08-26-verification.json"
)
DEFAULT_EWHC_VERIFICATION = (
    PROJECT_ROOT
    / "data/review_queue/seminar-gap-official-ewhc-divisions-2026-08-26-verification.json"
)
DEFAULT_ALIAS_RECONCILIATION = (
    PROJECT_ROOT / "data/review_queue/seminar-gap-legislation-alias-reconciliation-2026-08-26.json"
)
DEFAULT_FCL_SEARCH_RECOVERY = (
    PROJECT_ROOT / "config/seminar_gap_official_fcl_search_recovery.2026-08-26.v1.json"
)
DEFAULT_JSON = PROJECT_ROOT / "data/reports/seminar-gap-priority-queue-2026-08-26-v4.json"
DEFAULT_MARKDOWN = PROJECT_ROOT / "docs/reports/seminar-gap-priority-queue-2026-08-26-v4.md"
SCHEMA = "legalbot.seminar-gap-priority-queue.v4"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("priority_queue_input_must_be_json_object")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_exclusive(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def build_report(
    *,
    manifest_path: Path,
    audit_path: Path,
    verification_path: Path,
    legislation_resolution_path: Path,
    legislation_verification_path: Path,
    ewhc_verification_path: Path,
    alias_reconciliation_path: Path,
    fcl_search_recovery_path: Path,
) -> dict[str, Any]:
    manifest = _load(manifest_path)
    audit = _load(audit_path)
    verification = _load(verification_path)
    legislation_resolution = _load(legislation_resolution_path)
    legislation_verification = _load(legislation_verification_path)
    ewhc_verification = _load(ewhc_verification_path)
    alias_reconciliation = _load(alias_reconciliation_path)
    fcl_search_recovery = _load(fcl_search_recovery_path)
    if manifest.get("schema") != "legalbot.seminar-gap-official-uk-judgment-plan.v1":
        raise ValueError("priority_queue_manifest_schema_invalid")
    if audit.get("schema") != "legalbot.seminar-authority-coverage-audit.v3":
        raise ValueError("priority_queue_audit_schema_invalid")
    if verification.get("schema") != "legalbot.seminar-gap-uk-judgment-verification.v1":
        raise ValueError("priority_queue_verification_schema_invalid")
    if (
        legislation_resolution.get("schema")
        != "legalbot.seminar-gap-legislation-title-resolution.v1"
    ):
        raise ValueError("priority_queue_legislation_resolution_schema_invalid")
    if (
        legislation_verification.get("schema")
        != "legalbot.seminar-gap-official-legislation-verification.v1"
    ):
        raise ValueError("priority_queue_legislation_verification_schema_invalid")
    if (
        ewhc_verification.get("schema")
        != "legalbot.seminar-gap-official-ewhc-division-verification.v1"
    ):
        raise ValueError("priority_queue_ewhc_verification_schema_invalid")
    if (
        alias_reconciliation.get("schema")
        != "legalbot.seminar-gap-legislation-alias-reconciliation.v1"
    ):
        raise ValueError("priority_queue_alias_reconciliation_schema_invalid")
    if fcl_search_recovery.get("schema") != "legalbot.seminar-gap-official-fcl-search-recovery.v1":
        raise ValueError("priority_queue_fcl_search_recovery_schema_invalid")

    unresolved_by_reason: Counter[str] = Counter()
    unresolved_by_subject: dict[str, Counter[str]] = defaultdict(Counter)
    unresolved: list[dict[str, Any]] = []
    for item in manifest["unresolved_references"]:
        reason = str(item["reason_code"])
        subjects = sorted({str(value) for value in item.get("subjects", [])})
        unresolved_by_reason[reason] += 1
        for subject in subjects:
            unresolved_by_subject[subject][reason] += 1
        unresolved.append(
            {
                "authority_identity": str(item["authority_identity"]),
                "reason_code": reason,
                "subjects": subjects,
            }
        )

    unresolved = [item for item in unresolved if item["reason_code"] != "ewhc_division_missing"]
    unresolved.extend(
        {
            "authority_identity": str(item["authority_identity"]),
            "reason_code": "ewhc_division_official_identity_unresolved",
            "subjects": sorted(str(value) for value in item["subjects"]),
        }
        for item in ewhc_verification["still_unresolved"]
    )
    unresolved_by_reason = Counter(item["reason_code"] for item in unresolved)
    unresolved_by_subject = defaultdict(Counter)
    for item in unresolved:
        for subject in item["subjects"]:
            unresolved_by_subject[subject][item["reason_code"]] += 1

    legislation_by_subject: Counter[str] = Counter()
    presentation_legislation_missing = 0
    for reference in audit["references"]:
        if (
            reference.get("kind") != "legislation_title"
            or int(reference.get("presentation_document_count") or 0) <= 0
            or reference.get("coverage_status") != "catalogue_missing"
        ):
            continue
        presentation_legislation_missing += 1
        for subject in sorted({str(value) for value in reference.get("presentation_subjects", [])}):
            legislation_by_subject[subject] += 1

    verification_records = {
        str(item["authority_identity"]): item for item in verification["records"]
    }
    staged: list[dict[str, Any]] = []
    staged_by_subject: Counter[str] = Counter()
    for target in manifest["targets"]:
        identity = str(target["authority_identity"])
        record = verification_records.get(identity)
        if record is None:
            raise ValueError("priority_queue_verification_record_missing")
        subjects = sorted({str(value) for value in target["presentation_subjects"]})
        for subject in subjects:
            staged_by_subject[subject] += 1
        staged.append(
            {
                "authority_identity": identity,
                "content_sha256": str(target["content_sha256"]),
                "official_url": str(target["official_url"]),
                "subjects": subjects,
                "technical_verification_passed": bool(record["technical_verification_passed"]),
                "metadata_holds": sorted(str(value) for value in record["metadata_holds"]),
                "source_admission_gate": "OWNER_REVIEW_REQUIRED",
                "currentness_gate": "OWNER_REVIEW_REQUIRED",
                "later_treatment_gate": "OWNER_REVIEW_REQUIRED",
            }
        )

    legislation_urls = {
        str(match["canonical_url"])
        for record in legislation_resolution["records"]
        for match in record["official_exact_matches"]
    }
    alias_urls = {
        str(match["canonical_url"])
        for record in alias_reconciliation["records"]
        for match in record["official_exact_matches"]
    }
    legislation_verification_summary = legislation_verification["summary"]

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "as_of_date": "2026-08-26",
        "inputs": {
            "seminar_audit_sha256": _sha256(audit_path),
            "source_manifest_sha256": _sha256(manifest_path),
            "technical_verification_sha256": _sha256(verification_path),
            "legislation_resolution_sha256": _sha256(legislation_resolution_path),
            "legislation_verification_sha256": _sha256(legislation_verification_path),
            "ewhc_division_verification_sha256": _sha256(ewhc_verification_path),
            "legislation_alias_reconciliation_sha256": _sha256(alias_reconciliation_path),
            "fcl_search_recovery_sha256": _sha256(fcl_search_recovery_path),
        },
        "summary": {
            "official_uk_judgments_staged": len(staged),
            "official_uk_judgments_technical_passed": sum(
                item["technical_verification_passed"] for item in staged
            ),
            "already_staged_in_existing_official_pack": unresolved_by_reason[
                "already_staged_in_existing_official_pack"
            ],
            "find_case_law_exact_endpoint_unresolved": unresolved_by_reason[
                "find_case_law_http_error"
            ],
            "ewhc_division_identity_incomplete": ewhc_verification["summary"][
                "still_unresolved_count"
            ],
            "ewhc_division_newly_staged": ewhc_verification["summary"]["staged_target_count"],
            "ewhc_division_already_catalogued": ewhc_verification["summary"][
                "already_catalogued_count"
            ],
            "presentation_legislation_titles_requiring_normalisation": (
                presentation_legislation_missing
            ),
            "legislation_reference_rows_exact_resolved": legislation_resolution["summary"][
                "official_identity_resolved_count"
            ],
            "legislation_reference_rows_unresolved": legislation_resolution["summary"][
                "unresolved_count"
            ],
            "legislation_alias_rows_exact_owner_confirmation_required": (
                alias_reconciliation["summary"]["official_alias_exact_match_count"]
            ),
            "legislation_rows_still_unmapped_or_not_exact": (
                alias_reconciliation["summary"]["parent_unresolved_count"]
                - alias_reconciliation["summary"]["official_alias_exact_match_count"]
            ),
            "additional_unique_official_alias_candidates": len(alias_urls - legislation_urls),
            "official_alias_candidates_marked_repealed": sum(
                match.get("official_status_annotation") == "repealed"
                for record in alias_reconciliation["records"]
                for match in record["official_exact_matches"]
            ),
            "unique_official_legislation_identities": len(legislation_urls),
            "official_legislation_identities_already_catalogued": (
                len(legislation_urls) - legislation_verification_summary["authority_count"]
            ),
            "official_legislation_identities_newly_staged": (
                legislation_verification_summary["authority_count"]
            ),
            "official_legislation_identities_retrieval_ready": (
                legislation_verification_summary["retrieval_ready_authority_count"]
            ),
            "official_legislation_identities_ocr_held": legislation_verification_summary[
                "ocr_held_authority_count"
            ],
            "fcl_search_recovery_confirmed_unresolved": len(
                fcl_search_recovery["still_unresolved"]
            ),
        },
        "staged_by_subject": dict(sorted(staged_by_subject.items())),
        "unresolved_by_reason": dict(sorted(unresolved_by_reason.items())),
        "unresolved_by_subject": {
            subject: dict(sorted(counts.items()))
            for subject, counts in sorted(unresolved_by_subject.items())
        },
        "legislation_normalisation_queue_by_subject": dict(sorted(legislation_by_subject.items())),
        "legislation_ocr_holds": [
            authority["authority_identity"]
            for authority in legislation_verification["authorities"]
            if not authority["retrieval_ready"]
        ],
        "staged_official_judgments": staged,
        "unresolved_judgment_references": unresolved,
        "legislation_queue_policy": {
            "status": "NORMALISATION_REQUIRED_BEFORE_OFFICIAL_LOOKUP",
            "reason": (
                "Presentation extraction includes prose-prefixed or otherwise noisy titles; "
                "no title is treated as a legal identity until normalised and matched to an "
                "official legislation.gov.uk record."
            ),
        },
        "release_boundary": {
            "source_admission_authorized": False,
            "currentness_approval_authorized": False,
            "later_treatment_approval_authorized": False,
            "embedding_authorized": False,
            "candidate_mutation_authorized": False,
            "active_promotion_authorized": False,
            "development30_authorized": False,
            "validation30_authorized": False,
            "live_activation_authorized": False,
        },
    }
    encoded = json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    report["report_content_sha256"] = hashlib.sha256(encoded).hexdigest()
    return report


def _markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Seminar authority gap priority queue — 2026-08-26",
        "",
        "This is a non-authorising research and owner-review queue. Teaching materials are "
        "used only for gap discovery and never as legal authority.",
        "",
        "## Current result",
        "",
        f"- Official UK judgments staged: {summary['official_uk_judgments_staged']}",
        f"- Technical verification passed: {summary['official_uk_judgments_technical_passed']}",
        "- Already staged in the existing official pensions pack: "
        f"{summary['already_staged_in_existing_official_pack']}",
        "- Exact Find Case Law endpoint unresolved: "
        f"{summary['find_case_law_exact_endpoint_unresolved']}",
        "- EWHC citations requiring division disambiguation: "
        f"{summary['ewhc_division_identity_incomplete']}",
        "- EWHC division-resolved newly staged / already catalogued: "
        f"{summary['ewhc_division_newly_staged']} / "
        f"{summary['ewhc_division_already_catalogued']}",
        "- Presentation-extracted legislation titles requiring normalisation: "
        f"{summary['presentation_legislation_titles_requiring_normalisation']}",
        "- Legislation reference rows exact-resolved / unresolved: "
        f"{summary['legislation_reference_rows_exact_resolved']} / "
        f"{summary['legislation_reference_rows_unresolved']}",
        "- Unresolved rows with exact official alias candidates / still unmapped: "
        f"{summary['legislation_alias_rows_exact_owner_confirmation_required']} / "
        f"{summary['legislation_rows_still_unmapped_or_not_exact']}",
        "- Additional unique official alias candidates (not staged): "
        f"{summary['additional_unique_official_alias_candidates']}",
        "- Official alias candidates marked repealed: "
        f"{summary['official_alias_candidates_marked_repealed']}",
        "- Unique official legislation identities: "
        f"{summary['unique_official_legislation_identities']}",
        "- Already catalogued / newly staged legislation identities: "
        f"{summary['official_legislation_identities_already_catalogued']} / "
        f"{summary['official_legislation_identities_newly_staged']}",
        "- Newly staged retrieval-ready / OCR-held: "
        f"{summary['official_legislation_identities_retrieval_ready']} / "
        f"{summary['official_legislation_identities_ocr_held']}",
        "",
        "## Required sequence",
        "",
        "1. Resolve incomplete judgment identities and check other permitted official repositories.",
        "2. Normalise legislation references before official lookup; do not download prose-shaped false positives.",
        "3. Owner reviews source admission, jurisdiction/subject binding, currentness and later treatment.",
        "4. Only owner-approved sources may enter a new frozen candidate and embedding build.",
        "5. Calibration, qualification and the applicable owner gate remain required before promotion.",
        "",
        "No embedding, candidate mutation, ACTIVE write, Development 30, Validation 30 or live "
        "activation is authorised by this report.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--verification", type=Path, default=DEFAULT_VERIFICATION)
    parser.add_argument(
        "--legislation-resolution", type=Path, default=DEFAULT_LEGISLATION_RESOLUTION
    )
    parser.add_argument(
        "--legislation-verification", type=Path, default=DEFAULT_LEGISLATION_VERIFICATION
    )
    parser.add_argument("--ewhc-verification", type=Path, default=DEFAULT_EWHC_VERIFICATION)
    parser.add_argument("--alias-reconciliation", type=Path, default=DEFAULT_ALIAS_RECONCILIATION)
    parser.add_argument("--fcl-search-recovery", type=Path, default=DEFAULT_FCL_SEARCH_RECOVERY)
    parser.add_argument("--json-output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN)
    args = parser.parse_args()
    report = build_report(
        manifest_path=args.manifest,
        audit_path=args.audit,
        verification_path=args.verification,
        legislation_resolution_path=args.legislation_resolution,
        legislation_verification_path=args.legislation_verification,
        ewhc_verification_path=args.ewhc_verification,
        alias_reconciliation_path=args.alias_reconciliation,
        fcl_search_recovery_path=args.fcl_search_recovery,
    )
    _write_exclusive(
        args.json_output,
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n",
    )
    _write_exclusive(args.markdown_output, _markdown(report).encode("utf-8"))
    print(json.dumps(report["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
