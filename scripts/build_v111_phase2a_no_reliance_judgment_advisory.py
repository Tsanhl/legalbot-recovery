#!/usr/bin/env python3
"""Seal the six judgment versions with no Phase-2A 585-proposition reliance.

No-reliance is a scope fact, not a later-treatment conclusion.  This advisory
packet proposes conservative exclusion from the successor certification scope
and keeps related later-treatment leads quarantined.  Only the owner may adopt
those dispositions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OWNER_REVIEW_ROOT = PROJECT_ROOT / "data" / "evaluations" / "phase2a-owner-review"
SOURCE_ROOT = (
    OWNER_REVIEW_ROOT / "LegalBot-Phase2AB-2026-08-24-r47-consolidated-owner-gate"
)
DEFAULT_JUDGMENTS = SOURCE_ROOT / "COMPLETE-JUDGMENT-LATER-TREATMENT-REGISTER-20.json"
DEFAULT_SOURCES = SOURCE_ROOT / "SOURCE-CUSTODY-AND-ADMISSION-REGISTER.json"
DEFAULT_OUTPUT = (
    OWNER_REVIEW_ROOT
    / "LegalBot-Phase2AB-2026-08-25-r54-no-reliance-judgment-advisory"
)

EXPECTED_JUDGMENTS_CONTENT_SHA256 = (
    "f59c682b1162300fed741a226758d04492a9d39f796e336fca1788e019c336a4"
)
EXPECTED_SOURCES_CONTENT_SHA256 = (
    "3439b5f84ac6f0572fb74f5215f063582efe5c550b0fc4d521a4d7979435d384"
)
EXPECTED_NO_RELIANCE_SOURCE_VERSION_IDS = frozenset(
    {
        "source-version-17d7f9e7b7a587e6db6958328ed9ec16b827b40a",
        "source-version-f1b6faf51955805145857b51f2aab7fb70eea5e5",
        "source-version-c1f05b735bd3896e37a1ed43c1bd8a563ae61bb9",
        "source-version-df127bc6fa3c268460d204bb5188c0cbc4f8499e",
        "source-version-d7f6bbc94e3312bd3c8e2732336fa8ce4904dc50",
        "source-version-33739d3cbdd9a636888d599b41e9a516ba182fa7",
    }
)
EXPECTED_NO_RELIANCE_CITATIONS = frozenset(
    {"[2002] UKHL 12", "[2024] UKSC 8", "[2021] UKSC 5", "[2024] UKSC 12"}
)
EXPECTED_QUARANTINE_LEAD_IDS = frozenset(
    {
        "later-treatment-lead-001",
        "later-treatment-lead-002",
        "later-treatment-lead-005",
        "later-treatment-lead-006",
    }
)
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


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sealed(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("phase2a_no_reliance_input_must_be_regular_file")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("phase2a_no_reliance_input_must_be_object")
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


def _no_reliance_records(judgments: Mapping[str, Any]) -> list[dict[str, Any]]:
    records = judgments.get("records")
    if not isinstance(records, list) or len(records) != 20:
        raise ValueError("phase2a_no_reliance_judgment_records_invalid")
    selected: list[dict[str, Any]] = []
    for row in records:
        if not isinstance(row, dict):
            raise ValueError("phase2a_no_reliance_judgment_row_invalid")
        _verify_seal(
            row,
            "record_content_sha256",
            "phase2a_no_reliance_judgment_row_seal_invalid",
        )
        judgment = row.get("judgment_record")
        if not isinstance(judgment, dict):
            raise ValueError("phase2a_no_reliance_nested_judgment_invalid")
        _verify_seal(
            judgment,
            "packet_content_sha256",
            "phase2a_no_reliance_nested_judgment_seal_invalid",
        )
        source_version_id = str(judgment.get("source_version_id") or "")
        reference_count = judgment.get("unresolved_502_row_reference_count")
        references = judgment.get("unresolved_502_row_ids")
        if reference_count == 0:
            if (
                source_version_id not in EXPECTED_NO_RELIANCE_SOURCE_VERSION_IDS
                or references != []
                or judgment.get("approved_137_row_reference_count") != 0
                or row.get("owner_outcome") is not None
            ):
                raise ValueError("phase2a_no_reliance_zero_reference_boundary_invalid")
            selected.append(row)
    if (
        {row["judgment_record"]["source_version_id"] for row in selected}
        != EXPECTED_NO_RELIANCE_SOURCE_VERSION_IDS
        or {row["judgment_record"]["neutral_citation"] for row in selected}
        != EXPECTED_NO_RELIANCE_CITATIONS
    ):
        raise ValueError("phase2a_no_reliance_inventory_fingerprint_invalid")
    return selected


def _source_leads(sources: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    leads = sources.get("pending_later_treatment_sources")
    if (
        not isinstance(leads, list)
        or len(leads) != 9
        or sources.get("pending_later_treatment_source_count") != 9
    ):
        raise ValueError("phase2a_no_reliance_source_leads_invalid")
    quarantine: list[dict[str, Any]] = []
    remaining: list[dict[str, Any]] = []
    for lead in leads:
        if not isinstance(lead, dict):
            raise ValueError("phase2a_no_reliance_source_lead_invalid")
        _verify_seal(
            lead,
            "record_content_sha256",
            "phase2a_no_reliance_source_lead_seal_invalid",
        )
        if (
            lead.get("proposition_level_materiality_approved") is not False
            or lead.get("source_admitted") is not False
            or lead.get("indexed") is not False
            or lead.get("embedded") is not False
        ):
            raise ValueError("phase2a_no_reliance_source_lead_boundary_invalid")
        targets = lead.get("target_neutral_citations")
        if not isinstance(targets, list) or not targets:
            raise ValueError("phase2a_no_reliance_source_lead_targets_invalid")
        if set(str(target) for target in targets).issubset(EXPECTED_NO_RELIANCE_CITATIONS):
            quarantine.append(lead)
        else:
            remaining.append(lead)
    if {lead["lead_id"] for lead in quarantine} != EXPECTED_QUARANTINE_LEAD_IDS:
        raise ValueError("phase2a_no_reliance_source_lead_fingerprint_invalid")
    return quarantine, remaining


def build_no_reliance_advisory(
    *, judgments_path: Path, sources_path: Path, output_root: Path
) -> dict[str, Any]:
    """Create the no-reliance judgment and dependent-lead owner packet."""

    if output_root.exists() or output_root.is_symlink():
        raise ValueError("phase2a_no_reliance_output_already_exists")
    judgments = _load_object(judgments_path)
    judgments_sha256 = _verify_seal(
        judgments,
        "artifact_content_sha256",
        "phase2a_no_reliance_judgments_seal_invalid",
    )
    if judgments_sha256 != EXPECTED_JUDGMENTS_CONTENT_SHA256:
        raise ValueError("phase2a_no_reliance_judgments_identity_invalid")
    sources = _load_object(sources_path)
    sources_sha256 = _verify_seal(
        sources,
        "artifact_content_sha256",
        "phase2a_no_reliance_sources_seal_invalid",
    )
    if sources_sha256 != EXPECTED_SOURCES_CONTENT_SHA256:
        raise ValueError("phase2a_no_reliance_sources_identity_invalid")
    selected = _no_reliance_records(judgments)
    quarantined_leads, remaining_leads = _source_leads(sources)

    judgment_recommendations: list[dict[str, Any]] = []
    for row in selected:
        judgment = row["judgment_record"]
        material = {
            "schema": "legalbot.v111.phase2a.no-reliance-judgment-advisory-row.v1",
            "source_judgment_record_content_sha256": row["record_content_sha256"],
            "source_version_id": judgment["source_version_id"],
            "authority_identity_id": judgment["authority_identity"],
            "neutral_citation": judgment["neutral_citation"],
            "title": judgment["title"],
            "official_representation_id": judgment["official_representation_id"],
            "approved_137_row_reference_count": 0,
            "unresolved_502_row_reference_count": 0,
            "total_585_proposition_reference_count": 0,
            "scope_finding": "NO_585_PROPOSITION_RELIANCE_IDENTIFIED",
            "scope_finding_is_not_later_treatment_conclusion": True,
            "targeted_search_is_exhaustive": False,
            "advisory_recommendation": (
                "EXCLUDE_BECAUSE_NO_585_PROPOSITION_RELIANCE_AND_DO_NOT_REQUIRE_"
                "LATER_TREATMENT_FOR_THIS_CERTIFICATION_SCOPE"
            ),
            "owner_decision_options": [
                "EXCLUDE_BECAUSE_NO_585_PROPOSITION_RELIANCE",
                "RETAIN_AND_COMPLETE_LATER_TREATMENT_REVIEW",
                "REQUEST_MORE_EVIDENCE",
            ],
            "owner_outcome": None,
            "owner_decision_required": True,
            "source_admitted": False,
            "indexed": False,
            "embedded": False,
            "candidate_mutated": False,
            "technical_qualification_assigned": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        judgment_recommendations.append(
            {**material, "record_content_sha256": _sealed(material)}
        )

    lead_recommendations: list[dict[str, Any]] = []
    for lead in quarantined_leads:
        material = {
            "schema": "legalbot.v111.phase2a.no-reliance-dependent-lead-advisory-row.v1",
            "source_lead_record_content_sha256": lead["record_content_sha256"],
            "lead_id": lead["lead_id"],
            "candidate_case_name": lead["candidate_case_name"],
            "candidate_neutral_citation": lead["candidate_neutral_citation"],
            "target_neutral_citations": lead["target_neutral_citations"],
            "dependency_finding": (
                "ALL_TARGET_JUDGMENT_VERSIONS_HAVE_ZERO_585_PROPOSITION_RELIANCE"
            ),
            "dependency_finding_is_not_later_treatment_conclusion": True,
            "advisory_recommendation": "KEEP_QUARANTINED_AS_REVIEW_EVIDENCE_ONLY",
            "owner_decision_options": [
                "KEEP_QUARANTINED_AS_REVIEW_EVIDENCE_ONLY",
                "REQUEST_PROPOSITION_LEVEL_ADMISSION_REVIEW",
                "REJECT_SOURCE",
                "REQUEST_MORE_EVIDENCE",
            ],
            "owner_outcome": None,
            "owner_decision_required": True,
            "proposition_level_materiality_approved": False,
            "source_admitted": False,
            "indexed": False,
            "embedded": False,
            "candidate_mutated": False,
            "phase2b_authorized": False,
            "development30_authorized": False,
        }
        lead_recommendations.append(
            {**material, "record_content_sha256": _sealed(material)}
        )

    material = {
        "schema": "legalbot.v111.phase2a.no-reliance-judgment-advisory.v1",
        "status": "NO_RELIANCE_SCOPE_VERIFIED_OWNER_DECISIONS_REQUIRED",
        "source_judgments_content_sha256": judgments_sha256,
        "source_custody_and_admission_content_sha256": sources_sha256,
        "judgment_recommendation_count": len(judgment_recommendations),
        "judgment_recommendations": judgment_recommendations,
        "dependent_quarantine_lead_recommendation_count": len(lead_recommendations),
        "dependent_quarantine_lead_recommendations": lead_recommendations,
        "remaining_conditional_later_treatment_lead_count": len(remaining_leads),
        "remaining_conditional_later_treatment_lead_ids": [
            str(lead["lead_id"]) for lead in remaining_leads
        ],
        "absence_of_reliance_proves_no_later_treatment": False,
        "owner_decisions_applied": False,
        "source_admission_authorized": False,
        "automatic_indexing": False,
        "automatic_embedding": False,
        "candidate_mutated": False,
        "technical_qualification_assigned": False,
        "phase2b_authorized": False,
        "development30_authorized": False,
    }
    artifact = {**material, "artifact_content_sha256": _sealed(material)}
    output_root.mkdir(parents=True, mode=0o700)
    if stat.S_IMODE(output_root.stat().st_mode) != 0o700:
        raise ValueError("phase2a_no_reliance_output_mode_invalid")
    name = "NO-585-RELIANCE-JUDGMENT-ADVISORY-6.json"
    _write_exclusive(output_root / name, _pretty_json(artifact))
    outcome = (
        "SIX JUDGMENT SOURCE VERSIONS HAVE ZERO 585-PROPOSITION REFERENCES. "
        "EXCLUSION AND FOUR DEPENDENT QUARANTINE-LEAD DECISIONS REQUIRE OWNER APPROVAL. "
        "PHASE 2B AND DEVELOPMENT 30 NOT AUTHORIZED.\n"
    )
    _write_exclusive(output_root / "OUTCOME.txt", outcome.encode())
    sums = "".join(
        f"{_sha256_file(output_root / item)}  {item}\n" for item in (name, "OUTCOME.txt")
    )
    _write_exclusive(output_root / "SHA256SUMS.txt", sums.encode())
    return artifact


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--judgments", type=Path, default=DEFAULT_JUDGMENTS)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    result = build_no_reliance_advisory(
        judgments_path=args.judgments,
        sources_path=args.sources,
        output_root=args.output_root,
    )
    print(
        json.dumps(
            {
                "output_root": str(args.output_root),
                "status": result["status"],
                "judgment_recommendation_count": result[
                    "judgment_recommendation_count"
                ],
                "dependent_quarantine_lead_recommendation_count": result[
                    "dependent_quarantine_lead_recommendation_count"
                ],
                "artifact_content_sha256": result["artifact_content_sha256"],
                "phase2b_authorized": result["phase2b_authorized"],
                "development30_authorized": result["development30_authorized"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
