#!/usr/bin/env python3
"""Build the blocked, non-authorizing v1.11 Phase-2A review package."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.config import Settings  # noqa: E402
from app.evaluation.live_suite import (  # noqa: E402
    load_live_evaluation_bundle,
    sealed_sha256,
)
from app.evaluation.v111_certification_preparation import (  # noqa: E402
    exact_clean_code_binding,
    load_phase2_candidate_and_retrieval_evidence,
    open_immutable_phase2_catalogue,
    verify_phase2_preparation_package,
)
from app.evaluation.v111_phase2a_package import (  # noqa: E402
    ARTIFACT_IDS,
    IssueDispositionInput,
    Phase2AActionAbsenceAudit,
    Phase2AArtifact,
    Phase2ACandidateBinding,
    Phase2ACodeBinding,
    Phase2AExternalOfficialFinding,
    Phase2APackage,
    Phase2APackageIndex,
    Phase2AReviewInputs,
    build_phase2a_package,
    phase2a_package_json_payloads,
    verify_phase2a_package,
)
from app.retrieval.service import (  # noqa: E402
    PINNED_EMBEDDING_FILE_MANIFEST_SHA256,
    PINNED_EMBEDDING_REPO,
    PINNED_EMBEDDING_REVISION,
    PINNED_RERANKER_FILE_MANIFEST_SHA256,
    PINNED_RERANKER_REPO,
    PINNED_RERANKER_REVISION,
    _local_model_file_manifest_sha256,
    _production_embedding_identity,
    _production_reranker_identity,
    _verified_local_model,
)

CANDIDATE_ID: Literal["current-law-ew-full-fp16-v111-20260818-a"] = (
    "current-law-ew-full-fp16-v111-20260818-a"
)
BUNDLE_ROOT = PROJECT_ROOT / "benchmarks/evaluation/live-evaluation-60-v1"
BUILD_ROOT = PROJECT_ROOT / "data/indexes/builds" / CANDIDATE_ID
SOURCE_MANIFEST = BUILD_ROOT / "approved-source-manifest.json"
PREPARATION_ROOT = (
    PROJECT_ROOT
    / "data/evaluations/phase2-preparation"
    / "v111-phase2-preparation-20260822-r2-4f88665c13fe"
)
OUTPUT_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-currentness"
SYNTHETIC_TEST = "backend/tests/test_v111_phase2a_synthetic_split.py"
OFFICIAL_RETRIEVED_AT = datetime(2026, 8, 22, 14, 51, 42, tzinfo=UTC)
OFFICIAL_DOCUMENT_RETRIEVED_AT = datetime(2026, 8, 22, 15, 23, 13, tzinfo=UTC)
_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_URL_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _finding(
    finding_id: str,
    source_class: str,
    title: str,
    identifier: str,
    url: str,
    content_sha256: str,
    authority_date: date,
    status_code: str,
    affected_cases: tuple[str, ...],
) -> Phase2AExternalOfficialFinding:
    return Phase2AExternalOfficialFinding.model_validate(
        {
            "finding_id": finding_id,
            "source_class": source_class,
            "official_title": title,
            "official_identifier": identifier,
            "canonical_url": url,
            "retrieved_at": OFFICIAL_RETRIEVED_AT,
            "retrieved_content_sha256": content_sha256,
            # The Phase2A v1 transport schema predates the richer temporal
            # record below.  For legislation this required legacy field carries
            # the Royal Assent date only; it is never treated as a single
            # commencement/effective date.  For judgments it carries delivery.
            "legal_effect_date": authority_date,
            "authority_status_code": status_code,
            "affected_case_ids": affected_cases,
            "candidate_present": False,
            "materiality": "MATERIAL",
            "candidate_rebuild_required": True,
        }
    )


OFFICIAL_FINDINGS = (
    _finding(
        "gap-renters-rights-act-2025",
        "OFFICIAL_LEGISLATION",
        "Renters' Rights Act 2025",
        "2025-c-26",
        "https://www.legislation.gov.uk/ukpga/2025/26/pdfs/ukpga_20250026_en.pdf",
        "5aa96df1deb68461766aad07811e5dbb5bcf9fa46ef525fbc60cdf1753c78d57",
        date(2025, 10, 27),
        "royal-assent-recorded-provision-review-required",
        ("live60-q35",),
    ),
    _finding(
        "gap-data-use-access-act-2025",
        "OFFICIAL_LEGISLATION",
        "Data (Use and Access) Act 2025",
        "2025-c-18",
        "https://www.legislation.gov.uk/ukpga/2025/18/pdfs/ukpga_20250018_en.pdf",
        "a67c955f68a17bef5d496e0cd47aca8dbfed29574a62d8ede3717637227c163a",
        date(2025, 6, 19),
        "royal-assent-recorded-provision-review-required",
        ("live30-q23", "live60-q46", "live60-q51", "live60-q60"),
    ),
    _finding(
        "gap-property-digital-assets-act-2025",
        "OFFICIAL_LEGISLATION",
        "Property (Digital Assets etc) Act 2025",
        "2025-c-29",
        "https://www.legislation.gov.uk/ukpga/2025/29/pdfs/ukpga_20250029_en.pdf",
        "8b4936ead80a99ab1731472eb98fb26823c89fc8f02111d70d1f56fff56068fa",
        date(2025, 12, 2),
        "royal-assent-recorded-provision-review-required",
        ("live60-q60",),
    ),
    _finding(
        "gap-employment-rights-act-2025",
        "OFFICIAL_LEGISLATION",
        "Employment Rights Act 2025",
        "2025-c-36",
        "https://www.legislation.gov.uk/ukpga/2025/36/pdfs/ukpga_20250036_en.pdf",
        "bc4617677678746a471449d626d593ea350a89bad14a6e7677d2100af4110c4b",
        date(2025, 12, 18),
        "royal-assent-recorded-provision-review-required",
        ("live30-q07", "live60-q54"),
    ),
    _finding(
        "gap-border-security-asylum-immigration-act-2025",
        "OFFICIAL_LEGISLATION",
        "Border Security, Asylum and Immigration Act 2025",
        "2025-c-31",
        "https://www.legislation.gov.uk/ukpga/2025/31/pdfs/ukpga_20250031_en.pdf",
        "064e0c53cdabaf7285660eae594c538c7d11096a23de5e950531a9ebeb9057ef",
        date(2025, 12, 2),
        "royal-assent-recorded-provision-review-required",
        ("live60-q41",),
    ),
    _finding(
        "gap-planning-infrastructure-act-2025",
        "OFFICIAL_LEGISLATION",
        "Planning and Infrastructure Act 2025",
        "2025-c-34",
        "https://www.legislation.gov.uk/ukpga/2025/34/pdfs/ukpga_20250034_en.pdf",
        "2f4f540d469ba580eac3399a5380916828e56a42e7e3f6501df76312a75f666c",
        date(2025, 12, 18),
        "royal-assent-recorded-provision-review-required",
        ("live60-q40", "live60-q58"),
    ),
    _finding(
        "gap-stevens-2025-uksc-28",
        "OFFICIAL_BINDING_JUDGMENT",
        "Stevens v Hotel Portfolio II UK Ltd",
        "2025-UKSC-28",
        "https://supremecourt.uk/cases/judgments/uksc-2023-0142",
        "48d57b5f42063bfd4c4ea55c698e1428be60fa6c30c92f0650d8633072261f5e",
        date(2025, 7, 23),
        "binding-judgment-before-review-target",
        ("live30-q10", "live60-q60"),
    ),
    _finding(
        "gap-thg-zedra-2026-uksc-6",
        "OFFICIAL_BINDING_JUDGMENT",
        "THG Plc v Zedra Trust Company (Jersey) Ltd",
        "2026-UKSC-6",
        "https://supremecourt.uk/cases/judgments/uksc-2024-0047",
        "40f74633c5bec2305a39847e5eedac0ce9e88a0778f900379132149c9e28c409",
        date(2026, 2, 25),
        "binding-judgment-before-review-target",
        ("live30-q10",),
    ),
    _finding(
        "gap-gatwick-2026-uksc-14",
        "OFFICIAL_BINDING_JUDGMENT",
        "Gatwick Investment Ltd v Liberty Mutual Insurance Europe SE",
        "2026-UKSC-14",
        "https://supremecourt.uk/cases/uksc-2025-0067",
        "2d2cd8ad91e293d77b2b6e8f5c758fead9181287aada34ef1e0b4ecafbf6e1d0",
        date(2026, 4, 22),
        "binding-judgment-before-review-target",
        ("live60-q50",),
    ),
    _finding(
        "gap-axa-2026-uksc-24",
        "OFFICIAL_BINDING_JUDGMENT",
        "AXA Insurance UK PLC v Commissioners of Inland Revenue",
        "2026-UKSC-24",
        "https://www.supremecourt.uk/cases/judgments/uksc-2025-0005",
        "65c1ea0499cc597745261430001de7a16762beadb28cc7243941eb5b72f3fcc8",
        date(2026, 7, 27),
        "binding-judgment-before-review-target",
        ("live60-q59",),
    ),
    _finding(
        "gap-augustine-2026-uksc-30",
        "OFFICIAL_BINDING_JUDGMENT",
        "Augustine v Data Cars Limited",
        "2026-UKSC-30",
        "https://supremecourt.uk/cases/uksc-2025-0122",
        "d5f5f8cbd3f16027b70fc51f57bab6173f274706d8cc57809f120e88e5fd2671",
        date(2026, 8, 12),
        "binding-judgment-before-review-target",
        ("live30-q07",),
    ),
)


def _issue_rows(case_id: str, *issue_numbers: int) -> tuple[str, ...]:
    return tuple(f"{case_id}:issue-{number:02d}" for number in issue_numbers)


def _canonical_official_url_identity(value: str) -> str:
    parsed = urlsplit(value)
    hostname = (parsed.hostname or "").casefold()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    decoded_path = _PERCENT_ESCAPE.sub(
        lambda match: (
            chr(int(match.group(1), 16))
            if chr(int(match.group(1), 16)) in _URL_UNRESERVED
            else f"%{match.group(1).upper()}"
        ),
        parsed.path,
    )
    path = posixpath.normpath(decoded_path) if decoded_path else "/"
    if not path.startswith("/"):
        path = f"/{path}"
    path = path.rstrip("/") or "/"
    return f"{parsed.scheme.casefold()}://{hostname}{path}"


# These are proposition-review targets, not positive holdings.  The mapping is
# deliberately explicit so a candidate-change claim cannot float at case level
# while every issue row continues to say that no candidate change is known.
FINDING_AFFECTED_ISSUE_ROWS: dict[str, tuple[str, ...]] = {
    "gap-renters-rights-act-2025": _issue_rows("live60-q35", 1, 2, 4, 5, 6, 7, 8, 9),
    "gap-data-use-access-act-2025": (
        *_issue_rows("live30-q23", 1, 2, 3, 4, 5, 6, 7, 9),
        *_issue_rows("live60-q46", 4, 7),
        *_issue_rows("live60-q51", 4),
        *_issue_rows("live60-q60", 19),
    ),
    "gap-property-digital-assets-act-2025": _issue_rows(
        "live60-q60", 1, 2, 3, 4, 5, 6, 7, 8, 23, 24, 25
    ),
    "gap-employment-rights-act-2025": (
        *_issue_rows("live30-q07", 1, 9),
        *_issue_rows("live60-q54", 8, 9, 12),
    ),
    "gap-border-security-asylum-immigration-act-2025": _issue_rows(
        "live60-q41", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    ),
    "gap-planning-infrastructure-act-2025": (
        *_issue_rows("live60-q40", 1, 2, 5, 6, 7, 8, 9),
        *_issue_rows("live60-q58", 1, 2, 6, 7, 14),
    ),
    "gap-stevens-2025-uksc-28": (
        *_issue_rows("live30-q10", 1, 3, 7),
        *_issue_rows("live60-q60", 2, 5, 6, 7, 11, 23),
    ),
    "gap-thg-zedra-2026-uksc-6": _issue_rows("live30-q10", 6, 7),
    "gap-gatwick-2026-uksc-14": _issue_rows("live60-q50", 1, 2, 5, 9, 10),
    "gap-axa-2026-uksc-24": _issue_rows("live60-q59", 1, 3, 4, 7, 9, 20),
    "gap-augustine-2026-uksc-30": _issue_rows("live30-q07", 7, 8, 9),
}


FINDING_AUTHORITY_IDENTITIES: dict[str, str] = {
    "gap-renters-rights-act-2025": "ukpga:2025:26",
    "gap-data-use-access-act-2025": "ukpga:2025:18",
    "gap-property-digital-assets-act-2025": "ukpga:2025:29",
    "gap-employment-rights-act-2025": "ukpga:2025:36",
    "gap-border-security-asylum-immigration-act-2025": "ukpga:2025:31",
    "gap-planning-infrastructure-act-2025": "ukpga:2025:34",
    "gap-stevens-2025-uksc-28": "neutral-citation:[2025] UKSC 28",
    "gap-thg-zedra-2026-uksc-6": "neutral-citation:[2026] UKSC 6",
    "gap-gatwick-2026-uksc-14": "neutral-citation:[2026] UKSC 14",
    "gap-axa-2026-uksc-24": "neutral-citation:[2026] UKSC 24",
    "gap-augustine-2026-uksc-30": "neutral-citation:[2026] UKSC 30",
}


# The six legislation records bind the exact official enacted PDF already
# named by the core finding.  UKSC landing pages are mutable locators, so their
# core hashes are not used as judgment-content proof.  The five judgment
# records instead bind the official National Archives judgment PDF.
FINDING_DOCUMENT_IDENTITIES: dict[str, dict[str, str]] = {
    "gap-renters-rights-act-2025": {
        "version_identity": "ukpga:2025:26:enacted-pdf",
        "content_url": ("https://www.legislation.gov.uk/ukpga/2025/26/pdfs/ukpga_20250026_en.pdf"),
        "content_sha256": "5aa96df1deb68461766aad07811e5dbb5bcf9fa46ef525fbc60cdf1753c78d57",
    },
    "gap-data-use-access-act-2025": {
        "version_identity": "ukpga:2025:18:enacted-pdf",
        "content_url": ("https://www.legislation.gov.uk/ukpga/2025/18/pdfs/ukpga_20250018_en.pdf"),
        "content_sha256": "a67c955f68a17bef5d496e0cd47aca8dbfed29574a62d8ede3717637227c163a",
    },
    "gap-property-digital-assets-act-2025": {
        "version_identity": "ukpga:2025:29:enacted-pdf",
        "content_url": ("https://www.legislation.gov.uk/ukpga/2025/29/pdfs/ukpga_20250029_en.pdf"),
        "content_sha256": "8b4936ead80a99ab1731472eb98fb26823c89fc8f02111d70d1f56fff56068fa",
    },
    "gap-employment-rights-act-2025": {
        "version_identity": "ukpga:2025:36:enacted-pdf",
        "content_url": ("https://www.legislation.gov.uk/ukpga/2025/36/pdfs/ukpga_20250036_en.pdf"),
        "content_sha256": "bc4617677678746a471449d626d593ea350a89bad14a6e7677d2100af4110c4b",
    },
    "gap-border-security-asylum-immigration-act-2025": {
        "version_identity": "ukpga:2025:31:enacted-pdf",
        "content_url": ("https://www.legislation.gov.uk/ukpga/2025/31/pdfs/ukpga_20250031_en.pdf"),
        "content_sha256": "064e0c53cdabaf7285660eae594c538c7d11096a23de5e950531a9ebeb9057ef",
    },
    "gap-planning-infrastructure-act-2025": {
        "version_identity": "ukpga:2025:34:enacted-pdf",
        "content_url": ("https://www.legislation.gov.uk/ukpga/2025/34/pdfs/ukpga_20250034_en.pdf"),
        "content_sha256": "2f4f540d469ba580eac3399a5380916828e56a42e7e3f6501df76312a75f666c",
    },
    "gap-stevens-2025-uksc-28": {
        "version_identity": "neutral-citation:[2025] UKSC 28:judgment-pdf",
        "content_url": "https://caselaw.nationalarchives.gov.uk/uksc/2025/28/data.pdf",
        "content_sha256": "763b4a648214259a9ecccff97b0514ee1fe400c508b30969c87a71152a8c8efe",
    },
    "gap-thg-zedra-2026-uksc-6": {
        "version_identity": "neutral-citation:[2026] UKSC 6:judgment-pdf",
        "content_url": "https://caselaw.nationalarchives.gov.uk/uksc/2026/6/data.pdf",
        "content_sha256": "19aadc85acb420d7b2864332a1c7e2d0b7b9dd344593e48e64fb9d7c3b2ed371",
    },
    "gap-gatwick-2026-uksc-14": {
        "version_identity": "neutral-citation:[2026] UKSC 14:judgment-pdf",
        "content_url": "https://caselaw.nationalarchives.gov.uk/uksc/2026/14/data.pdf",
        "content_sha256": "4206c2cf03ddb5d3041699bb32445f1584a2ce5fa38845c4d91134069c30424b",
    },
    "gap-axa-2026-uksc-24": {
        "version_identity": "neutral-citation:[2026] UKSC 24:judgment-pdf",
        "content_url": "https://caselaw.nationalarchives.gov.uk/uksc/2026/24/data.pdf",
        "content_sha256": "673fca341f7e474ca85a50ea092508e2a75be8180db6eb7703c11c298f49b0ec",
    },
    "gap-augustine-2026-uksc-30": {
        "version_identity": "neutral-citation:[2026] UKSC 30:judgment-pdf",
        "content_url": "https://caselaw.nationalarchives.gov.uk/uksc/2026/30/data.pdf",
        "content_sha256": "e062ff2467a4af5567f6a2e9de483f06090ca91c670398212f6b3fe1a88ec7ea",
    },
}


def _finding_review_records(
    *, bundle: Any, candidate_source_manifest: Mapping[str, Any]
) -> tuple[dict[str, Any], ...]:
    registry_rows = {
        f"{case.case_id}:issue-{number:02d}"
        for case in bundle.registry.cases
        for number, _label in enumerate(case.must_cover_issues, start=1)
    }
    findings_by_id = {item.finding_id: item for item in OFFICIAL_FINDINGS}
    expected_ids = set(findings_by_id)
    if (
        set(FINDING_AFFECTED_ISSUE_ROWS) != expected_ids
        or set(FINDING_AUTHORITY_IDENTITIES) != expected_ids
        or set(FINDING_DOCUMENT_IDENTITIES) != expected_ids
    ):
        raise RuntimeError("phase2a_official_finding_binding_incomplete")
    raw_sources = candidate_source_manifest.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise RuntimeError("phase2a_candidate_source_inventory_invalid")
    records: list[dict[str, Any]] = []
    for finding_id in sorted(expected_ids):
        finding = findings_by_id[finding_id]
        affected_rows = FINDING_AFFECTED_ISSUE_ROWS[finding_id]
        if (
            not affected_rows
            or len(affected_rows) != len(set(affected_rows))
            or not set(affected_rows).issubset(registry_rows)
            or {row_id.split(":", 1)[0] for row_id in affected_rows}
            != set(finding.affected_case_ids)
        ):
            raise RuntimeError("phase2a_official_finding_issue_mapping_invalid")
        authority_identity = FINDING_AUTHORITY_IDENTITIES[finding_id]
        document = FINDING_DOCUMENT_IDENTITIES[finding_id]
        authority_matches = []
        content_matches = []
        url_matches = []
        for raw_source in raw_sources:
            if not isinstance(raw_source, Mapping):
                raise RuntimeError("phase2a_candidate_source_inventory_invalid")
            observed_authority = str(raw_source.get("authority_identity_id") or "")
            observed_stable = str(raw_source.get("stable_identifier") or "")
            if (
                observed_authority == authority_identity
                or observed_stable == authority_identity
                or observed_stable.startswith(f"{authority_identity}:")
            ):
                authority_matches.append(str(raw_source.get("source_version_id") or ""))
            if document["content_sha256"] in {
                str(raw_source.get("content_sha256") or ""),
                str(raw_source.get("version_sha256") or ""),
            }:
                content_matches.append(str(raw_source.get("source_version_id") or ""))
            if _canonical_official_url_identity(str(raw_source.get("canonical_url") or "")) in {
                _canonical_official_url_identity(finding.canonical_url),
                _canonical_official_url_identity(document["content_url"]),
            }:
                url_matches.append(str(raw_source.get("source_version_id") or ""))
        if authority_matches or content_matches or url_matches:
            raise RuntimeError("phase2a_external_finding_present_in_candidate")
        is_legislation = finding.source_class == "OFFICIAL_LEGISLATION"
        content_identity = {
            "authority_identity": authority_identity,
            "version_identity": document["version_identity"],
            "content_url": document["content_url"],
            "content_sha256": document["content_sha256"],
            "media_type": "application/pdf",
            "observed_at": OFFICIAL_DOCUMENT_RETRIEVED_AT.isoformat(),
            "official_content_role": (
                "OFFICIAL_ENACTED_PDF_BYTES" if is_legislation else "OFFICIAL_JUDGMENT_PDF_BYTES"
            ),
            "content_bytes_embedded_in_package": False,
            "content_bytes_retrieved_by_builder": False,
            "content_digest_is_external_review_observation": True,
        }
        content_identity["identity_sha256"] = sealed_sha256(content_identity)
        temporal = {
            "authority_date": finding.legal_effect_date.isoformat(),
            "authority_date_kind": (
                "ROYAL_ASSENT_DATE" if is_legislation else "JUDGMENT_DELIVERY_DATE"
            ),
            "legacy_legal_effect_date_field_semantics": (
                "ROYAL_ASSENT_ONLY_NOT_COMMENCEMENT_OR_EFFECTIVE_DATE"
                if is_legislation
                else "JUDGMENT_DELIVERY_DATE"
            ),
            "single_effective_date_claimed": False,
            "per_provision_commencement_effective_transition_state": (
                "REVIEW_REQUIRED_NOT_COMPLETED" if is_legislation else "NOT_APPLICABLE_TO_JUDGMENT"
            ),
        }
        temporal["temporal_identity_sha256"] = sealed_sha256(temporal)
        absence = {
            "scope": "SEALED_APPROVED_SOURCE_MANIFEST_ONLY",
            "candidate_source_manifest_sha256": str(
                candidate_source_manifest.get("manifest_sha256") or ""
            ),
            "authority_identity_match_count": 0,
            "official_document_content_match_count": 0,
            "exact_official_url_match_count": 0,
            "does_not_claim_absence_from_arbitrary_host_or_unconfigured_sources": True,
        }
        absence["observation_sha256"] = sealed_sha256(absence)
        review_record: dict[str, Any] = {
            "finding_id": finding_id,
            "affected_issue_row_ids": affected_rows,
            "affected_issue_row_set_sha256": sealed_sha256(
                {
                    "schema": "legalbot.v111-phase2a-finding-issue-row-set.v1",
                    "finding_id": finding_id,
                    "row_ids": affected_rows,
                }
            ),
            "mapping_state": "PROPOSITION_REVIEW_REQUIRED_NOT_POSITIVE_HOLDING",
            "core_canonical_url_role": (
                "OFFICIAL_DOCUMENT_CONTENT"
                if is_legislation
                else "MUTABLE_OFFICIAL_LOCATOR_ONLY_NOT_CONTENT_PROOF"
            ),
            "core_retrieved_content_sha256_role": (
                "OFFICIAL_DOCUMENT_CONTENT"
                if is_legislation
                else "MUTABLE_LOCATOR_SNAPSHOT_ONLY_NOT_CONTENT_PROOF"
            ),
            "document_content_identity": content_identity,
            "temporal_status": temporal,
            "candidate_absence_observation": absence,
        }
        review_record["core_finding_binding_sha256"] = sealed_sha256(
            {
                "schema": "legalbot.v111-phase2a-core-finding-binding.v1",
                "finding": finding.model_dump(mode="json"),
                "affected_issue_row_ids": affected_rows,
                "document_content_identity_sha256": content_identity["identity_sha256"],
                "temporal_identity_sha256": temporal["temporal_identity_sha256"],
                "candidate_absence_observation_sha256": absence["observation_sha256"],
            }
        )
        review_record["record_sha256"] = sealed_sha256(review_record)
        records.append(review_record)
    return tuple(records)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output-directory", required=True, type=Path)
    return parser


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _git(*args: str) -> str:
    result = subprocess.run(
        ("git", *args),
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _remote_ref_sha(ref: str) -> str:
    result = subprocess.run(
        ("git", "ls-remote", "--exit-code", "origin", ref),
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    fields = result.stdout.strip().split()
    if len(fields) != 2 or fields[1] != ref or len(fields[0]) != 40:
        raise RuntimeError("remote_ref_identity_invalid")
    return fields[0]


def _path_proposal(*components: str) -> dict[str, Any]:
    rendered = "/" + "/".join(components)
    return {
        "path_kind": "ABSOLUTE_POSIX",
        "components": components,
        "render_rule": "prefix-single-slash-and-join-components",
        "rendered_sha256": _sha256_bytes(rendered.encode()),
    }


def _run_synthetic_split_tests() -> dict[str, Any]:
    command = ("uv", "run", "--python", "3.13", "pytest", "-q", SYNTHETIC_TEST)
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=False,
    )
    record = {
        "schema": "legalbot.v111-phase2a-synthetic-split-test-result.v1",
        "command_sha256": _sha256_bytes("\0".join(command).encode()),
        "test_file_sha256": _sha256_path(PROJECT_ROOT / SYNTHETIC_TEST),
        "exit_code": result.returncode,
        "stdout_sha256": _sha256_bytes(result.stdout),
        "stderr_sha256": _sha256_bytes(result.stderr),
        "synthetic_case_count": 60,
        "real_registry_partitioned": False,
        "real_secret_generated": False,
        "real_lane_identities_emitted": False,
    }
    record["record_sha256"] = sealed_sha256(record)
    if result.returncode != 0:
        raise RuntimeError("synthetic_split_verification_failed")
    return record


def _absence_audit() -> tuple[Phase2AActionAbsenceAudit, dict[str, Any]]:
    proposed_root = Path("/Users/Shared/LegalBot-v111-Private")
    explicit_paths = {
        "active_pointer": PROJECT_ROOT / "data/indexes/ACTIVE.json",
        "previous_pointer": PROJECT_ROOT / "data/indexes/PREVIOUS.json",
        "owner_control_root": proposed_root,
        "development_review_root": proposed_root / "development-review",
        "sealed_validation_root": proposed_root / "sealed-validation-custody",
        "live_review_root": proposed_root / "live-review",
        "model_socket": proposed_root / "model/model.sock",
        "owner_public_key": proposed_root / "owner-key/owner-ed25519.pub",
        "local_session_material": proposed_root / "session/session-secret",
    }
    present = tuple(sorted(name for name, path in explicit_paths.items() if path.exists()))
    if present:
        raise RuntimeError("phase2a_forbidden_state_present")
    scoped_searches = {
        "real_split": tuple(OUTPUT_ROOT.glob("**/*certification-split*"))
        if OUTPUT_ROOT.exists()
        else (),
        "development_projection": tuple(OUTPUT_ROOT.glob("**/*development-projection*"))
        if OUTPUT_ROOT.exists()
        else (),
        "stage_a_result": tuple(OUTPUT_ROOT.glob("**/*stage-a-result*"))
        if OUTPUT_ROOT.exists()
        else (),
        "answer_model_result": tuple(OUTPUT_ROOT.glob("**/*model-result*"))
        if OUTPUT_ROOT.exists()
        else (),
        "partition_randomness_persistence": (
            tuple(OUTPUT_ROOT.glob("**/*split-secret*"))
            + tuple(OUTPUT_ROOT.glob("**/*secret-commitment*"))
        )
        if OUTPUT_ROOT.exists()
        else (),
        "owner_approval_cryptographic_artifact": (
            tuple(OUTPUT_ROOT.glob("**/*owner-signature*"))
            + tuple(OUTPUT_ROOT.glob("**/*signing-payload*"))
        )
        if OUTPUT_ROOT.exists()
        else (),
    }
    if any(scoped_searches.values()):
        raise RuntimeError("phase2a_scoped_runtime_state_present")
    details: dict[str, Any] = {
        "schema": "legalbot.v111-phase2a-action-absence-observation.v1",
        "explicit_identity_count": len(explicit_paths),
        "explicit_present_count": 0,
        "scoped_search_match_counts": {
            key: len(value) for key, value in sorted(scoped_searches.items())
        },
        "scope": "configured-v111-phase2a-and-proposed-owner-control-identities",
        "claim_scope": (
            "exact-active-previous-paths-dedicated-owner-control-root-and-phase2a-output-root"
        ),
        "dedicated_owner_control_root_absent": True,
        "partition_randomness_persistent_locations_checked": True,
        "does_not_claim_process-memory-ephemeral-randomness-absence": True,
        "does_not_claim_arbitrary-host-forensic-absence": True,
    }
    details["audit_sha256"] = sealed_sha256(details)
    audit = Phase2AActionAbsenceAudit(
        audit_sha256=details["audit_sha256"],
        active_pointer_absent=True,
        previous_pointer_absent=True,
        real_split_absent=True,
        real_split_secret_absent=True,
        signing_key_absent=True,
        session_secret_absent=True,
        real_review_roots_absent=True,
        stage_a_results_absent=True,
        answer_model_results_absent=True,
        development_projection_absent=True,
    )
    return audit, details


def _candidate_binding(*, settings: Settings, code: Any) -> Phase2ACandidateBinding:
    with open_immutable_phase2_catalogue(settings.database_path) as database:
        sealed_candidate, _retrieval_evidence = load_phase2_candidate_and_retrieval_evidence(
            settings=settings,
            database=database,
            candidate_build_id=CANDIDATE_ID,
            code=code,
        )
    manifest = json.loads((BUILD_ROOT / "manifest.json").read_text(encoding="utf-8"))
    source_manifest = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    embedding_root = _verified_local_model(
        settings.embedding_model_path,
        PINNED_EMBEDDING_REPO,
        PINNED_EMBEDDING_REVISION,
        expected_file_manifest_sha256=PINNED_EMBEDDING_FILE_MANIFEST_SHA256,
    )
    reranker_root = _verified_local_model(
        settings.reranker_model_path,
        PINNED_RERANKER_REPO,
        PINNED_RERANKER_REVISION,
        expected_file_manifest_sha256=PINNED_RERANKER_FILE_MANIFEST_SHA256,
    )
    embedding_store_sha256 = _local_model_file_manifest_sha256(embedding_root)
    reranker_store_sha256 = _local_model_file_manifest_sha256(reranker_root)
    if (
        sealed_candidate.build_id != CANDIDATE_ID
        or sealed_candidate.status != "candidate"
        or sealed_candidate.embedding_model != _production_embedding_identity(settings)
        or sealed_candidate.reranker_model != _production_reranker_identity(settings)
        or source_manifest.get("source_count") != sealed_candidate.document_count
        or source_manifest.get("chunk_count") != sealed_candidate.chunk_count
        or manifest.get("chunk_count") != sealed_candidate.chunk_count
        or manifest.get("vector_dimensions") != 1024
        or source_manifest.get("manifest_sha256") != sealed_candidate.source_manifest_sha256
        or _sha256_path(BUILD_ROOT / "manifest.json") != sealed_candidate.candidate_manifest_sha256
        or _sha256_path(BUILD_ROOT / "seal.json") != sealed_candidate.candidate_seal_sha256
        or embedding_store_sha256 != PINNED_EMBEDDING_FILE_MANIFEST_SHA256
        or reranker_store_sha256 != PINNED_RERANKER_FILE_MANIFEST_SHA256
    ):
        raise RuntimeError("exact_candidate_binding_failed")
    return Phase2ACandidateBinding.model_validate(
        {
            "build_id": sealed_candidate.build_id,
            "candidate_manifest_sha256": sealed_candidate.candidate_manifest_sha256,
            "candidate_seal_file_sha256": sealed_candidate.candidate_seal_sha256,
            "approved_source_manifest_sha256": sealed_candidate.source_manifest_sha256,
            "approved_source_manifest_file_sha256": _sha256_path(SOURCE_MANIFEST),
            "embedding_store_sha256": embedding_store_sha256,
            "reranker_store_sha256": reranker_store_sha256,
            "document_count": sealed_candidate.document_count,
            "chunk_count": sealed_candidate.chunk_count,
            "vector_count": sealed_candidate.vector_count,
            "dimensions": int(manifest["vector_dimensions"]),
        }
    )


def _details(
    *,
    code_commit: str,
    code_tree: str,
    action_audit: Mapping[str, Any],
    synthetic: Mapping[str, Any],
    finding_review_records: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    security = {
        "proposal_state": "PROPOSED_NOT_CREATED_NOT_AUTHORIZING",
        "future_key_scheme": {
            "algorithm": "Ed25519",
            "private_key_format": "encrypted-pkcs8",
            "private_key_custody": "owner-offline-only-mode-0600",
            "public_key_format": "subject-public-key-info-pem",
            "public_key_location": _path_proposal(
                "Users", "Shared", "LegalBot-v111-Private", "owner-key", "owner-ed25519.pub"
            ),
            "fingerprint": "sha256-lowercase-hex-of-canonical-raw-32-byte-public-key",
            "future_signing_domain": "LEGALBOT-V111-OWNER-DECISION-ED25519-V1-NUL",
            "future_json_rule": "rfc8785-style-canonical-json-plus-newline",
            "detached_output_bytes": 64,
            "revocation": "append-only-owner-signed-revocation-and-replacement",
        },
        "model_transport": {
            "socket_location": _path_proposal(
                "Users", "Shared", "LegalBot-v111-Private", "model", "model.sock"
            ),
            "owner_mode": "current-effective-uid-mode-0600",
            "allowed_model_id": "mlx-community/Qwen3.5-9B-4bit",
            "allowed_revision": "8b2b98c00a6b4d291155e4890773ca8f769aee53",
            "file_manifest_sha256": (
                "17c7421bc514d5e9eef293aeedc7ec3e8c4712391aac1eec44eec4add6b97470"
            ),
            "runtime_model_sha256": (
                "1d4172150e0b972bbf600bb42e1dc0f293cf4878a6abe221fe664ad353a5ed1b"
            ),
            "identity_seal_sha256": (
                "4bb625aeb1ad76cf1a15508c339a421402b0f6fbf5363b8593668fa38a71bf05"
            ),
            "tcp_http_cloud_fallback_allowed": False,
            "environment_proxy_trust": False,
            "transport_retries": 0,
            "maximum_connections": 1,
            "timeout_and_token_fences_required": True,
            "failure_mode": "fail-closed-no-result-publication",
        },
        "resources": {
            "aggregate_legalbot_process_memory_bytes": 12884901888,
            "minimum_free_host_memory_bytes": 3221225472,
            "preflight_required": True,
            "monitor_interval_seconds": 1,
            "limit_action": "cancel-and-hard-stop-owned-child-tree",
            "incomplete_run_disposition": "failed-no-partial-publication",
        },
        "private_roots": (
            {
                "lane": "development-review",
                "location": _path_proposal(
                    "Users", "Shared", "LegalBot-v111-Private", "development-review"
                ),
            },
            {
                "lane": "sealed-validation-custody",
                "location": _path_proposal(
                    "Users", "Shared", "LegalBot-v111-Private", "sealed-validation-custody"
                ),
            },
            {
                "lane": "ordinary-live-review",
                "location": _path_proposal(
                    "Users", "Shared", "LegalBot-v111-Private", "live-review"
                ),
            },
        ),
        "root_policy": {
            "directory_mode": "0700",
            "file_mode": "0600",
            "owner": "current-effective-uid",
            "symlinks_hardlinks_allowed": False,
            "cloud_or_sync_ancestor_allowed": False,
            "cross-lane_projection_allowed": False,
            "archive_policy": "create-only-versioned-owner-controlled",
            "deletion_policy": "owner-explicit-only-after-verified-archive",
        },
        "local_application": {
            "bind_host": "127.0.0.1",
            "bind_port": 8777,
            "host_allowlist": ("127.0.0.1:8777",),
            "origin_allowlist": ("http://127.0.0.1:8777",),
            "csrf_design": "per-session-random-double-submit-header-x-legalbot-csrf",
            "session_cookie_name": "legalbot_owner_session",
            "session_material_location": _path_proposal(
                "Users", "Shared", "LegalBot-v111-Private", "session", "session-secret"
            ),
            "session_material_mode": "0600",
            "rotation": "every-process-start-and-after-security-event",
            "wildcard_lan_public_bind_allowed": False,
            "log_redaction": "no-case-prose-no-answer-prose-no-private-path-no-control-material",
        },
    }
    contract = {
        "state": "CONSERVATIVE_PROPOSAL_NOT_FROZEN",
        "registry_case_count": 60,
        "registry_issue_count": 585,
        "legal_currentness_cutoff": "OWNER_PENDING_AFTER_SUCCESSOR_CANDIDATE",
        "source_hierarchy": (
            "official-legislation",
            "official-binding-judgment",
            "official-rules-or-practice-direction",
            "official-regulator-or-government-governing-material",
        ),
        "scoring": {
            "automated_academic_target": 70,
            "automated_target_is_legal_safety_gate": False,
            "issue_pass": "positive-source-and-span-binding-with-zero-material-unsupported-claims",
            "case_pass": "every-required-issue-passes-and-owner-adjudication-passes",
            "aggregation": "no-average-masks-case-or-issue-failure",
            "validation_required_case_passes": 30,
            "required_release_state": "verified_full",
        },
        "hard_zero_tolerances": {
            "invented_authority": 0,
            "false_quotation": 0,
            "material_contradiction": 0,
            "unsupported_material_assertion": 0,
            "private-path-or-owner-identifier": 0,
            "teaching-or-feedback-as-independent-authority": 0,
        },
        "evidence": {
            "material_claim_requires_frozen_evidence_span": True,
            "source_identity_jurisdiction_currentness_required": True,
            "model_rendered_citations_allowed": False,
            "oscola_generation": "deterministic-from-reviewed-metadata",
            "insufficient_evidence": "abstain-or-verified-limited-never-invent",
        },
        "retrieval_gate": {
            "recall_at_5_minimum": 1.0,
            "recall_at_10_minimum": 0.95,
            "mrr_minimum": 0.8,
            "filter_violation_maximum": 0,
        },
        "execution": {
            "generation_concurrency": 1,
            "same_failure_fingerprint_maximum": 2,
            "transient_attempt_limit_per_case": 2,
            "quality_motivated_selective_rerun_allowed": False,
            "preflight_failure_consumes_sealed_run": False,
            "run_begins": "first-committed-generation-request",
            "resume": "same-run-authenticated-checkpoint-unchanged-snapshot-unexposed-output-only",
            "missing_case": "failure-unless-frozen-invalid-run-rule-applies",
            "results_exposure_ends_sealed-status": True,
        },
        "review_and_adjudication": {
            "human-owner-adjudication_required": True,
            "reviewer_versions_frozen_before-run": True,
            "disagreement_resolution": "preserve-both-records-owner-reasoned-final-decision",
            "rubric_or-threshold-relaxation-after-results": False,
        },
        "preservation": {
            "prior-cycles-immutable": True,
            "create-only-artifacts": True,
            "ordinary-logs-contain-case-or-answer-prose": False,
            "cloud-publication-training-export": False,
        },
        "change_invalidation": "apply-v111-roadmap-change-to-gate-matrix",
    }
    freshness = {
        "official_primary_sources_only": True,
        "monitoring_frequency": "daily-during-certification",
        "delta_checks": (
            "within-24-hours-before-development-30",
            "within-24-hours-before-o04",
            "within-24-hours-before-owner-only-live",
        ),
        "material_if_can_change": (
            "legal-answer",
            "element-defence-remedy-procedure",
            "limitation-or-deadline",
            "governing-test-or-burden",
            "required-form-or-filing-route",
            "authority-or-version-cited",
            "evidence-admissibility-or-reliability",
            "expected-gold-span",
            "case-disposition",
        ),
        "enacted_not_commenced": "record-pending-and-disclose-if-material-not-current-until-effective",
        "commencement_and_transition": "bind-effective-date-and-savings-to-each-affected-proposition",
        "royal_assent_is_not_commencement": True,
        "single-act-wide-effective-date_inference_allowed": False,
        "per-provision-commencement-effective-transition-review-required": True,
        "new_binding_judgment": "material-unless-reviewed-and-reasoned-irrelevant",
        "official_source_correction": "reverify-digest-and-materiality-before-reuse",
        "material_consequence": (
            "new-candidate-seal",
            "affected-qualification",
            "retrieval-reattestation",
            "final-development-rerun",
            "renewed-owner-acceptance-and-downstream-evidence",
        ),
        "silent_candidate_bound_update_allowed": False,
    }
    cutoff = {
        "recommended_common_cutoff": None,
        "review_target_ceiling": "2026-08-14T23:59:59+01:00",
        "timezone": "Europe/London",
        "support_status": "UNSUPPORTABLE_ON_CURRENT_CANDIDATE",
        "reason": "material-pre-target-official-authorities-absent-and-all585-gold-bindings-empty",
        "constraining_finding_ids": tuple(item.finding_id for item in OFFICIAL_FINDINGS),
        "source_verification_range": (
            "2026-08-22T14:51:42Z",
            "2026-08-22T14:51:42Z",
        ),
        "known_post-target-treatment": "outside-target-requires-separate-delta-review",
        "alternative_earlier_cutoff": None,
        "earlier_cutoff_risk_reduction": "none-because-foundational-gold-and-source-family-gaps-persist",
        "owner_authoritative": False,
    }
    official_method = {
        "authority": "official-primary-only",
        "candidate_membership_test": (
            "sealed-approved-source-manifest-authority-url-and-content-identity-replay"
        ),
        "source_bytes": (
            "external-official-review-content-digests-recorded-by-stable-document-identity"
        ),
        "external_document_bytes_embedded": False,
        "external_document_bytes_retrieved_by_builder": False,
        "external_content_observation_replayable_from-package-alone": False,
        "mutable-judgment-landing-pages-used-as-content-proof": False,
        "official-judgment-pdf-content-identities-recorded": True,
        "answer-history-used": False,
        "stage-a-used": False,
        "legal-proposition-review_complete": False,
        "blocking-review-sufficient-to-stop": True,
        "stop_reason": "confirmed-material-candidate-omissions-and-zero-positive-gold-bindings",
    }
    companion_sources = (
        {
            "identifier": "SI-2026-421",
            "content_sha256": ("b4546bc784445f899d63b3899a92b279615fd2e8efb2c65fabb8bd3d87090009"),
            "status_code": "commencement-instrument-observed-provision-mapping-required",
            "single-effective-date_claimed": False,
        },
        {
            "identifier": "SI-2026-82",
            "content_sha256": ("fbf2618450b4e3642de83c5456bf3f36e3841c146ba7d86527831b5ec4c72201"),
            "status_code": "commencement-and-transition-instrument-observed-provision-mapping-required",
            "single-effective-date_claimed": False,
        },
        {
            "identifier": "SI-2026-3",
            "content_sha256": ("8d6a76c752bf9c020a389f6729af49aeacf3d6540739953490f6bad21e6fc116"),
            "status_code": "commencement-instrument-observed-provision-mapping-required",
            "single-effective-date_claimed": False,
        },
        {
            "identifier": "SI-2026-373",
            "content_sha256": ("90f9b8ce092eea1b8aaf5c35d2bc6ac6846ffb995774a4b4600ca58c124a7ec5"),
            "status_code": "commencement-instrument-observed-provision-mapping-required",
            "single-effective-date_claimed": False,
        },
        {
            "identifier": "SI-2025-1318",
            "content_sha256": ("34ddb446558dc8135aca86a04f39f0174e88f7ea39ae9bd33be65077dd2e909b"),
            "status_code": "commencement-instrument-observed-provision-mapping-required",
            "single-effective-date_claimed": False,
        },
    )
    remediation_families = (
        "housing-and-building-safety",
        "data-protection-privacy-and-cyber",
        "employment-pensions-and-restructuring",
        "immigration-asylum-and-human-rights",
        "planning-environment-energy-and-infrastructure",
        "company-insolvency-trusts-and-digital-assets",
        "insurance-and-collective-redress",
        "payments-financial-services-aml-sanctions-and-tax",
        "competition-procurement-charities-credit-and-regulatory-rules",
        "cross-border-and-international-authorities",
    )
    owner_choices = (
        {
            "decision_id": "P2A-D01",
            "decision": "authorize-successor-candidate-and-gold-remediation-work",
            "recommended": True,
            "current_effect": "required-before-any-phase2b",
        },
        {
            "decision_id": "P2A-D02",
            "decision": "appoint-or-provide-qualified-human-legal-reviewer-for-585-propositions",
            "recommended": True,
            "current_effect": "ai-alone-cannot-create-positive-legal-qualification",
        },
        {
            "decision_id": "P2A-D03",
            "decision": "approve-review-target-policy-not-a-frozen-cutoff",
            "recommended": True,
            "current_effect": "target-ceiling-only-until-successor-requalification",
        },
        {
            "decision_id": "P2A-D04",
            "decision": "approve-or-amend-conservative-certification-contract",
            "recommended": True,
            "current_effect": "proposal-only",
        },
        {
            "decision_id": "P2A-D05",
            "decision": "approve-or-amend-key-socket-resource-root-and-local-security-proposals",
            "recommended": True,
            "current_effect": "no-control-material-created",
        },
        {
            "decision_id": "P2A-D06",
            "decision": "withhold-phase2b-until-remediated-phase2a-package-passes",
            "recommended": True,
            "current_effect": "split-and-development-30-remain-not-authorized",
        },
    )
    return {
        "entry-state": {
            "branch": "codex/release-v111-integration",
            "code_commit": code_commit,
            "code_tree": code_tree,
            "starting_commit": "4f88665c13fef524ab050fb1f6ce9d7a4998fb22",
            "phase1_baseline_commit": "77bd27520a3a12f814e70de8ab5813fb13161b73",
            "phase1_baseline_tree": "fbc6d74bd4110471565bd9965b452e1ee5b4a761",
            "phase1_baseline_tag": "v1.11-integration-baseline-20260822-r8",
            "preparation_index_sha256": (
                "f316607eeef669f131a0d0998e52a9c61ed66c55abc11282f089637ba0351f2c"
            ),
            "action_absence_observation": dict(action_audit),
        },
        "issue-currentness-register": {
            "registry_binding_observation": {
                "case_count": 60,
                "issue_count": 585,
                "cases_with_acceptable_source_ids": 0,
                "cases_with_exact_gold_spans": 0,
                "positive_issue_qualification_count": 0,
            },
            "primary_status_policy": (
                "confirmed-mapped-candidate-gaps-take-priority-over-universal-empty-gold-defect"
            ),
            "unmapped_primary_status": "GOLD_OR_CASE_DEFECT",
            "mapped_primary_status": "MATERIAL_CANDIDATE_COVERAGE_GAP",
            "row_review_records_unique": True,
            "official_review_method": official_method,
        },
        "official-source-provenance-register": {
            "review_method": official_method,
            "candidate_source_audit": {
                "source_count": 85,
                "legislation_count": 65,
                "judgment_entry_count": 20,
                "full_current_law_eligible_count": 0,
                "legislation_unapplied_effect_count": 1896,
                "judgment_subsequent_treatment_required_count": 20,
                "judgment_subsequent_treatment_verified_count": 0,
            },
            "companion_official_records": companion_sources,
            "external_finding_review_records": tuple(finding_review_records),
            "external_finding_review_record_count": len(finding_review_records),
        },
        "case-qualification-register": {
            "qualified_case_count": 0,
            "blocked_case_count": 60,
            "verdict": "ALL_CASES_NOT_QUALIFIED",
        },
        "qualification-aggregate": {
            "qualified_issue_count": 0,
            "blocked_issue_count": 585,
            "accounted_exactly_once": True,
            "legal_qualification_complete": False,
        },
        "gap-conflict-register": {
            "confirmed_external_material_finding_ids": tuple(
                item.finding_id for item in OFFICIAL_FINDINGS
            ),
            "remediation_source_families": remediation_families,
            "unresolved_source_version_conflicts_hidden": False,
            "qualification_stop_applied": True,
            "finding_issue_row_mapping_count": len(finding_review_records),
            "candidate_change_issue_row_count": len(
                {
                    str(row_id)
                    for record in finding_review_records
                    for row_id in record["affected_issue_row_ids"]
                }
            ),
        },
        "candidate-impact-report": {
            "verdict": "SUCCESSOR_CANDIDATE_REQUIRED",
            "existing_candidate_mutated": False,
            "candidate_change_issue_row_count": len(
                {
                    str(row_id)
                    for record in finding_review_records
                    for row_id in record["affected_issue_row_ids"]
                }
            ),
            "required_steps": (
                "build-complete-official-authority-map-for-all585",
                "bind-reviewed-gold-and-evidence-spans-per-issue",
                "ingest-confirmed-missing-primary-authorities",
                "verify-extent-effective-date-amendment-transition-repeal-and-treatment",
                "seal-new-candidate",
                "rerun-retrieval-reattestation",
                "rerun-phase2a-on-successor",
            ),
            "invalidated_if-successor-built": (
                "candidate-seal-and-manifest",
                "candidate-bound-qualification",
                "retrieval-attestation",
                "development-and-all-downstream-evidence",
            ),
        },
        "cutoff-recommendation": cutoff,
        "freshness-material-change-policy": freshness,
        "security-owner-controls-proposal": security,
        "certification-contract-proposal": contract,
        "synthetic-split-verification": dict(synthetic),
        "owner-readable-summary": {
            "result": "BLOCKED_BEFORE_PHASE2B",
            "reason": "candidate-and-gold-currentness-defects",
            "owner_decision_count": len(owner_choices),
            "owner_choices": owner_choices,
        },
        "owner-decision-payload-draft": {
            "draft_state": "NONAUTHORIZING_RECOMMENDATIONS_ONLY",
            "decisions": owner_choices,
            "cutoff_proposal_sha256": sealed_sha256(cutoff),
            "freshness_proposal_sha256": sealed_sha256(freshness),
            "security_proposal_sha256": sealed_sha256(security),
            "contract_proposal_sha256": sealed_sha256(contract),
            "future_owner_signed_payload_deferred": True,
            "phase2b_authorized": False,
        },
        "final-invariants": {
            "safe_stop_verdict": (
                "PHASE 2A SAFELY STOPPED - SPLIT AND DEVELOPMENT 30 NOT AUTHORIZED"
            ),
            "all585_accounted": True,
            "candidate_bytes_unchanged": True,
            "owner_controls_created": False,
            "real_split_executed": False,
            "stage_a_executed": False,
            "answer_model_executed": False,
            "promotion_or_live_action": False,
        },
    }


def _blocked_dispositions(
    *,
    bundle: Any,
    review: Phase2AReviewInputs,
    finding_review_records: Sequence[Mapping[str, Any]],
) -> dict[str, IssueDispositionInput]:
    issue_support = sealed_sha256(
        {
            "schema": "legalbot.v111-phase2a-empty-gold-binding-observation.v1",
            "registry_sha256": bundle.registry.canonical_sha256,
            "case_count": 60,
            "issue_count": 585,
            "acceptable_source_binding_count": 0,
            "exact_gold_span_binding_count": 0,
        }
    )
    finding_records_by_id = {str(record["finding_id"]): record for record in finding_review_records}
    finding_ids_by_issue: dict[str, list[str]] = {}
    for finding_id, record in finding_records_by_id.items():
        for row_id in record["affected_issue_row_ids"]:
            finding_ids_by_issue.setdefault(str(row_id), []).append(finding_id)
    dispositions: dict[str, IssueDispositionInput] = {}
    for case in bundle.registry.cases:
        for issue_number, label in enumerate(case.must_cover_issues, start=1):
            row_id = f"{case.case_id}:issue-{issue_number:02d}"
            mapped_finding_ids = tuple(sorted(finding_ids_by_issue.get(row_id, ())))
            mapped_support = tuple(
                str(finding_records_by_id[finding_id]["record_sha256"])
                for finding_id in mapped_finding_ids
            )
            row_identity = sealed_sha256(
                {
                    "schema": "legalbot.v111-phase2a-blocked-issue-review-record.v1",
                    "row_id": row_id,
                    "case_record_sha256": case.record_sha256,
                    "issue_label_sha256": _sha256_bytes(label.encode()),
                    "review_method_sha256": review.official_source_review_method_sha256,
                    "binding_gap_sha256": issue_support,
                    "external_official_finding_ids": mapped_finding_ids,
                    "external_official_finding_record_sha256s": mapped_support,
                }
            )
            dispositions[row_id] = IssueDispositionInput(
                primary_status=(
                    "MATERIAL_CANDIDATE_COVERAGE_GAP"
                    if mapped_finding_ids
                    else "GOLD_OR_CASE_DEFECT"
                ),
                official_review_record_sha256=row_identity,
                reason_code=(
                    "confirmed-material-authority-and-registry-gold-binding-absent"
                    if mapped_finding_ids
                    else "registry-gold-source-span-bindings-absent"
                ),
                supporting_evidence_sha256s=(
                    issue_support,
                    bundle.registry.canonical_sha256,
                    *mapped_support,
                ),
                affected_proposition_state=(
                    "MAPPED_MATERIAL_GAP" if mapped_finding_ids else "UNMAPPABLE_WITHOUT_GOLD"
                ),
                prevents_common_cutoff=True,
                remediation_code=(
                    "successor-candidate-and-human-gold-binding"
                    if mapped_finding_ids
                    else "human-review-bind-official-source-and-gold-span"
                ),
                candidate_bytes_change_required=True if mapped_finding_ids else None,
                owner_approval_required=True,
                external_official_finding_ids=mapped_finding_ids,
            )
    return dispositions


def _write_package(output: Path, package: Phase2APackage) -> None:
    payloads = phase2a_package_json_payloads(package)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    try:
        for name, payload in payloads.items():
            descriptor = os.open(
                output / name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        if stat.S_IMODE(output.stat().st_mode) != 0o700:
            raise RuntimeError("phase2a_output_directory_mode_invalid")
        if any(
            stat.S_IMODE(path.stat().st_mode) != 0o600 or path.stat().st_nlink != 1
            for path in output.iterdir()
        ):
            raise RuntimeError("phase2a_output_member_identity_invalid")
    except BaseException:
        shutil.rmtree(output)
        raise


def _replay(
    output: Path,
    bundle: Any,
    manifest: Mapping[str, Any],
    *,
    candidate_replay_binding: Phase2ACandidateBinding,
    expected_artifact_payload_extensions: Mapping[str, Mapping[str, Any]],
) -> Phase2APackage:
    expected_names = {f"{artifact_id}.json" for artifact_id in ARTIFACT_IDS} | {
        "PHASE2A-INDEX.json"
    }
    if set(path.name for path in output.iterdir()) != expected_names:
        raise RuntimeError("phase2a_output_members_invalid")
    artifacts = tuple(
        Phase2AArtifact.model_validate(json.loads((output / f"{artifact_id}.json").read_bytes()))
        for artifact_id in ARTIFACT_IDS
    )
    index = Phase2APackageIndex.model_validate(
        json.loads((output / "PHASE2A-INDEX.json").read_bytes())
    )
    package = Phase2APackage(artifacts=artifacts, index=index)
    verify_phase2a_package(
        package,
        bundle=bundle,
        candidate_source_manifest=manifest,
        candidate_replay_binding=candidate_replay_binding,
        expected_artifact_payload_extensions=expected_artifact_payload_extensions,
    )
    if phase2a_package_json_payloads(package) != {
        path.name: path.read_bytes() for path in output.iterdir()
    }:
        raise RuntimeError("phase2a_output_replay_bytes_mismatch")
    return package


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = args.output_directory.resolve()
    allowed = OUTPUT_ROOT.resolve()
    if not output.is_relative_to(allowed) or output == allowed or output.exists():
        raise SystemExit("phase2a_output_location_invalid")
    if _git("branch", "--show-current") != "codex/release-v111-integration":
        raise SystemExit("phase2a_branch_invalid")
    settings = Settings(project_root=PROJECT_ROOT)
    if (
        settings.test_mode
        or settings.online_default != "local_only"
        or settings.official_research_enabled
    ):
        raise SystemExit("phase2a_offline_non_test_profile_required")
    exact = exact_clean_code_binding(PROJECT_ROOT, expected_head=args.expected_head)
    if _git("rev-list", "--left-right", "--count", "HEAD...@{upstream}") != "0\t0":
        raise SystemExit("phase2a_upstream_state_invalid")
    if _git("rev-parse", "v1.11-integration-baseline-20260822-r8^{commit}") != (
        "77bd27520a3a12f814e70de8ab5813fb13161b73"
    ):
        raise SystemExit("phase1_checkpoint_changed")
    preparation = verify_phase2_preparation_package(PREPARATION_ROOT.resolve(strict=True))
    if preparation.index_sha256 != (
        "f316607eeef669f131a0d0998e52a9c61ed66c55abc11282f089637ba0351f2c"
    ):
        raise SystemExit("phase2_preparation_changed")
    candidate = _candidate_binding(settings=settings, code=exact)
    bundle = load_live_evaluation_bundle(BUNDLE_ROOT.resolve(strict=True))
    if (
        len(bundle.registry.cases) != 60
        or sum(len(case.must_cover_issues) for case in bundle.registry.cases) != 585
        or any(
            case.acceptable_source_ids or case.exact_gold_spans for case in bundle.registry.cases
        )
    ):
        raise SystemExit("phase2a_registry_binding_state_changed")
    manifest = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    finding_review_records = _finding_review_records(
        bundle=bundle,
        candidate_source_manifest=manifest,
    )
    action_audit, action_details = _absence_audit()
    synthetic = _run_synthetic_split_tests()
    if exact_clean_code_binding(PROJECT_ROOT, expected_head=args.expected_head) != exact:
        raise SystemExit("phase2a_code_binding_changed_during_review")

    extensions = _details(
        code_commit=exact.commit_sha,
        code_tree=exact.tree_sha,
        action_audit=action_details,
        synthetic=synthetic,
        finding_review_records=finding_review_records,
    )
    entry_state = {
        "code": exact.model_dump(mode="json"),
        "candidate": candidate.model_dump(mode="json"),
        "registry_sha256": bundle.registry.canonical_sha256,
        "preparation_index_sha256": preparation.index_sha256,
        "action_absence_audit_sha256": action_audit.audit_sha256,
        "remote_main_sha": _remote_ref_sha("refs/heads/main"),
        "phase1_tag_commit": _git("rev-parse", "v1.11-integration-baseline-20260822-r8^{commit}"),
    }
    official_method = extensions["official-source-provenance-register"]["review_method"]
    cutoff = extensions["cutoff-recommendation"]
    freshness = extensions["freshness-material-change-policy"]
    security = extensions["security-owner-controls-proposal"]
    contract = extensions["certification-contract-proposal"]
    review = Phase2AReviewInputs(
        generated_at=datetime.now(UTC),
        code=Phase2ACodeBinding(
            commit_sha=exact.commit_sha,
            tree_sha=exact.tree_sha,
            worktree_clean=True,
        ),
        candidate=candidate,
        action_absence_audit=action_audit,
        entry_state_sha256=sealed_sha256(entry_state),
        official_source_review_method_sha256=sealed_sha256(official_method),
        recommended_cutoff_date=None,
        review_target_cutoff_date=date(2026, 8, 14),
        cutoff_support_status="UNSUPPORTABLE_ON_CURRENT_CANDIDATE",
        cutoff_basis_sha256=sealed_sha256(cutoff),
        freshness_policy_sha256=sealed_sha256(freshness),
        security_controls_proposal_sha256=sealed_sha256(security),
        certification_contract_proposal_sha256=sealed_sha256(contract),
        synthetic_split_verification_sha256=str(synthetic["record_sha256"]),
        synthetic_split_verification_passed=True,
        terminal_verdict="BLOCKED_MATERIAL_GAPS",
        candidate_rebuild_required=True,
        confirmed_material_candidate_finding_count=len(OFFICIAL_FINDINGS),
    )
    dispositions = _blocked_dispositions(
        bundle=bundle,
        review=review,
        finding_review_records=finding_review_records,
    )
    package = build_phase2a_package(
        bundle=bundle,
        candidate_source_manifest=manifest,
        review=review,
        dispositions=dispositions,
        external_official_findings=OFFICIAL_FINDINGS,
        artifact_payload_extensions=extensions,
    )
    _write_package(output, package)
    candidate_after_write = _candidate_binding(settings=settings, code=exact)
    if candidate_after_write != candidate:
        raise SystemExit("phase2a_candidate_changed_during_review")
    replay = _replay(
        output,
        bundle,
        manifest,
        candidate_replay_binding=candidate_after_write,
        expected_artifact_payload_extensions=extensions,
    )
    if replay.index != package.index:
        raise SystemExit("phase2a_package_replay_mismatch")
    if exact_clean_code_binding(PROJECT_ROOT, expected_head=args.expected_head) != exact:
        raise SystemExit("phase2a_final_code_binding_changed")
    print(
        json.dumps(
            {
                "schema": "legalbot.v111-phase2a-build-result.v1",
                "status": "blocked_material_gaps",
                "authorizing": False,
                "commit_sha": exact.commit_sha,
                "tree_sha": exact.tree_sha,
                "case_count": 60,
                "issue_count": 585,
                "qualified_issue_count": 0,
                "external_material_finding_count": len(OFFICIAL_FINDINGS),
                "candidate_rebuild_required": True,
                "real_split_created": False,
                "stage_a_invoked": False,
                "answer_model_invoked": False,
                "index_sha256": package.index.index_sha256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
