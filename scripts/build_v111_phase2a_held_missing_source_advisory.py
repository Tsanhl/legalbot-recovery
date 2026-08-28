#!/usr/bin/env python3
"""Build the create-only Phase-2A advisory for the assigned 8+20 rows.

This builder records bounded official-primary-source research.  It does not
apply an owner decision, admit or materialise a source, scan, build, embed,
retrieve, qualify, run an answer model, mutate ACTIVE/PREVIOUS, or start
Phase 2B.  Every row remains non-qualifying until a later exact owner packet
and the normal technical gates say otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = PROJECT_ROOT / "data/evaluations/phase2a-owner-review"

R3_REPORT = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-prequalification-blockers-r3"
    / "PREQUALIFICATION-BLOCKER-REPORT.json"
)
R3_REPORT_FILE_SHA256 = "7cb044a4c9539162281e10ac41e5e0cb1f0cd846b0eb597a0443b0e67fb48899"
R3_REPORT_CONTENT_SHA256 = "5efc17b16adcae1ceb2ea1bbd7efcaba469ab0340c24b65c1e994132cb337980"

OWNER_PACKET = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-28-exact-remediation-owner-packet-r1"
    / "EXACT-REMEDIATION-OWNER-PACKET-361.json"
)
OWNER_PACKET_FILE_SHA256 = "992770c04cb3e08de64bb98e80aa9801171d3e66e4b573b85919091a78b1db3b"
OWNER_PACKET_CONTENT_SHA256 = "93ad9113af76896f0570a3666c446472af7587b7e3ff32b7464e670777ec6b6c"

PRIOR_QUARANTINE_MANIFEST = (
    REVIEW_ROOT / "LegalBot-Phase2A-2026-08-28-source-quarantine" / "QUARANTINE-MANIFEST.json"
)
PRIOR_QUARANTINE_MANIFEST_FILE_SHA256 = (
    "f482366a2ba0d9f636c56104d632767a8eadd6e9a9625d50ef5391a5f62995eb"
)
PRIOR_QUARANTINE_MANIFEST_CONTENT_SHA256 = (
    "b6d900b23232379a4d6c19d313f35c47e0758ce5e0bb6eb04008f9eba07a3819"
)

CANDIDATE_MANIFEST = (
    REVIEW_ROOT
    / "LegalBot-Phase2A-2026-08-27-final-owner-review-blocked"
    / "machine/candidate/approved-source-manifest.json"
)
CANDIDATE_MANIFEST_FILE_SHA256 = "0bbb1edb169c84a26e5f1d42e367f9e2f83fcdd9c652a9061980652f15979b21"

QUARANTINE_ROOT = REVIEW_ROOT / (
    "LegalBot-Phase2A-2026-08-28-held-missing-source-research-quarantine-r1"
)
OFFICIAL_ROOT = QUARANTINE_ROOT / "official"
DEFAULT_OUTPUT_ROOT = REVIEW_ROOT / ("LegalBot-Phase2A-2026-08-28-held-missing-source-advisory-r2")

SUPERSEDED_R1_ADVISORY_CONTENT_SHA256 = (
    "73e77df0edb3b48ad3ce8116a149c861366df78828e29d22872f2fb3caf97194"
)
SUPERSEDED_R1_ADVISORY_FILE_SHA256 = (
    "919689a759f63d89b9a331af933c21dfd0e0f0c6386f3f7f293708d1325a4503"
)

ADVISORY_NAME = "HELD-MISSING-SOURCE-ADVISORY-28.json"
SOURCE_MANIFEST_NAME = "OFFICIAL-SOURCE-RESEARCH-MANIFEST.json"
RETRY_LEDGER_NAME = "FAILED-ROUTE-ANTI-RETRY-LEDGER.json"
PACKAGE_NAME = "PACKAGE-MANIFEST.json"
CHECKSUMS_NAME = "SHA256SUMS.txt"

HELD8 = (
    "live30-q01:issue-01",
    "live30-q01:issue-03",
    "live30-q05:issue-06",
    "live30-q19:issue-01",
    "live30-q19:issue-03",
    "live30-q19:issue-04",
    "live30-q24:issue-01",
    "live60-q42:issue-08",
)
HELD8_SET_SHA256 = "898cff2fed47d1ba0d0dc96a8b6423f8a85a68abc230d03ca8c569fa38bc0064"

MISSING20 = (
    "live30-q04:issue-07",
    "live30-q05:issue-07",
    "live30-q13:issue-04",
    "live30-q13:issue-08",
    "live30-q20:issue-08",
    "live30-q24:issue-08",
    "live30-q28:issue-05",
    "live30-q30:issue-07",
    "live30-q30:issue-10",
    "live30-q30:issue-16",
    "live30-q30:issue-18",
    "live60-q32:issue-04",
    "live60-q37:issue-06",
    "live60-q40:issue-09",
    "live60-q42:issue-03",
    "live60-q46:issue-05",
    "live60-q50:issue-06",
    "live60-q59:issue-14",
    "live60-q59:issue-15",
    "live60-q59:issue-17",
)
MISSING20_SET_SHA256 = "c1699db80b68ef40bce307314b063d0c7a64b35620d4e39e1d95ff7856977bb7"

STATUS_RESOLVED = "SOURCE_TOPOLOGY_RESOLVED_OWNER_ACTION_REQUIRED"
STATUS_REWRITE = "NO_VALID_MISSING_SOURCE_REQUIREMENT_OWNER_REWRITE_OR_EXCLUSION"
STATUS_RETAINED = "UNAVAILABLE_OR_INCOMPLETE_OFFICIAL_SOURCE_GAP_RETAINED"

NO_EXECUTION = {
    "owner_approved": False,
    "owner_decisions_applied": False,
    "source_admission_authorized": False,
    "source_admitted": False,
    "source_materialized": False,
    "source_scan_run": False,
    "successor_build_run": False,
    "index_built": False,
    "embedding_run": False,
    "retrieval_reattestation_run": False,
    "all585_qualification_run": False,
    "answer_model_run": False,
    "answer_released": False,
    "phase2b_authorized": False,
    "phase2b_run": False,
    "development30_run": False,
    "validation30_run": False,
    "promotion_run": False,
    "active_pointer_written": False,
    "previous_pointer_written": False,
    "live_activation_run": False,
    "training_export_run": False,
}

_PRIVATE_PATH = re.compile(r"(?i)(?:/Users/|/home/|/private/|file://|[A-Z]:\\Users\\)")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _pretty_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _content_sha256(value: Any) -> str:
    return _sha256(_canonical_json(value))


def _seal(value: Mapping[str, Any], field: str = "artifact_content_sha256") -> dict[str, Any]:
    output = dict(value)
    output.pop(field, None)
    output[field] = _content_sha256(output)
    return output


def _relative(file_path: Path) -> str:
    return file_path.relative_to(PROJECT_ROOT).as_posix()


SOURCE_FILES: tuple[dict[str, Any], ...] = (
    {
        "member": "001-r-v-johnson-2022-ewca-crim-832.xml",
        "raw_sha256": "be476478c4ad918d672a77c57e547a2821040c942dc05c3469e915502b375dbd",
        "authority_identity_id": "neutral-citation:[2022] EWCA Crim 832",
        "official_url": "https://caselaw.nationalarchives.gov.uk/ewca/crim/2022/832/data.xml",
        "media_type": "application/xml",
        "evidence_role": "PROPOSED_OWNER_ADMISSION_REPRESENTATION",
        "exact_locators": ["paragraphs 49-50"],
        "affected_row_ids": ["live30-q04:issue-07"],
        "jurisdiction_finding": "England and Wales; Court of Appeal (Criminal Division)",
        "source_role_finding": "binding appellate judgment for the stated duress test",
        "currentness_finding": "historical judgment identity and exact span verified",
        "later_treatment_finding": "comprehensive later-treatment check remains held",
    },
    {
        "member": "002-dyson-v-channel-four-2023-ewca-civ-884.xml",
        "raw_sha256": "ce0e82fe43281c8e51d42615e732373e18ad424625bb6b6b19b17408eb9930d3",
        "authority_identity_id": "neutral-citation:[2023] EWCA Civ 884",
        "official_url": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2023/884/data.xml",
        "media_type": "application/xml",
        "evidence_role": "PROPOSED_OWNER_ADMISSION_REPRESENTATION",
        "exact_locators": ["paragraphs 33-47", "paragraphs 49-60"],
        "affected_row_ids": ["live60-q32:issue-04"],
        "jurisdiction_finding": "England and Wales; Court of Appeal (Civil Division)",
        "source_role_finding": "binding appellate judgment on identification/reference",
        "currentness_finding": "historical judgment identity and exact spans verified",
        "later_treatment_finding": "comprehensive later-treatment check remains held",
    },
    {
        "member": "003-aib-group-2014-uksc-58-wrong-media-type.html",
        "raw_sha256": "777129443d430e9d3953a0d77af79c4476aa720a881e7cd1f0d86dfbbd8f91bb",
        "authority_identity_id": "neutral-citation:[2014] UKSC 58",
        "official_url": "https://supremecourt.uk/cases/docs/uksc-2013-0052-judgment.pdf",
        "media_type": "text/html",
        "evidence_role": "FAILED_ROUTE_DIAGNOSTIC_NOT_EVIDENCE",
        "exact_locators": [],
        "affected_row_ids": ["live30-q13:issue-08"],
        "jurisdiction_finding": "United Kingdom Supreme Court route",
        "source_role_finding": "HTTP success returned HTML, not judgment PDF",
        "currentness_finding": "not evidence",
        "later_treatment_finding": "not applicable",
    },
    {
        "member": "004-simon-v-lyder-2019-ukpc-38.pdf",
        "raw_sha256": "ce9cb3296a691045aac6d14de32cfc1b349c128a2f52c3477adf89d0e2229da5",
        "authority_identity_id": "neutral-citation:[2019] UKPC 38",
        "official_url": "https://jcpc.uk/uploads/jcpc_2018_0097_judgment_1f3c09c74d.pdf",
        "media_type": "application/pdf",
        "evidence_role": "RESEARCH_ONLY_PERSUASIVE_JURISDICTION_HOLD",
        "exact_locators": ["paragraphs 11-26"],
        "affected_row_ids": ["live60-q32:issue-04"],
        "jurisdiction_finding": "Privy Council appeal from Trinidad and Tobago",
        "source_role_finding": "persuasive only for the England-and-Wales target row",
        "currentness_finding": "historical judgment identity verified",
        "later_treatment_finding": "comprehensive later-treatment check remains held",
    },
    {
        "member": "005-john-doyle-2021-ewca-civ-1452.html",
        "raw_sha256": "9abc386781f925a4b37e030edcaa7a9a69554faf13e103cba728980477b89b6a",
        "authority_identity_id": "neutral-citation:[2021] EWCA Civ 1452",
        "official_url": "https://www.judiciary.uk/judgments/john-doyle-construction-limited-v-erith-contractors-limited/",
        "media_type": "text/html",
        "evidence_role": "IDENTITY_LANDING_ONLY_NOT_PROPOSITION_EVIDENCE",
        "exact_locators": [],
        "affected_row_ids": ["live60-q59:issue-15"],
        "jurisdiction_finding": "England and Wales; Court of Appeal identity confirmed",
        "source_role_finding": "official landing page does not contain proposition bytes",
        "currentness_finding": "identity only",
        "later_treatment_finding": "comprehensive later-treatment check remains held",
    },
    {
        "member": "006-axa-2026-uksc-24.html",
        "raw_sha256": "65c1ea0499cc597745261430001de7a16762beadb28cc7243941eb5b72f3fcc8",
        "authority_identity_id": "neutral-citation:[2026] UKSC 24",
        "official_url": "https://supremecourt.uk/cases/judgments/uksc-2025-0005",
        "media_type": "text/html",
        "evidence_role": "PROPOSED_OWNER_ADMISSION_REPRESENTATION",
        "exact_locators": ["paragraphs 1-3", "paragraphs 14-21", "paragraphs 185-188"],
        "affected_row_ids": ["live60-q59:issue-17"],
        "jurisdiction_finding": "United Kingdom Supreme Court",
        "source_role_finding": "binding Supreme Court judgment for the stated GLO mechanics",
        "currentness_finding": "official full judgment representation verified",
        "later_treatment_finding": "later-treatment check remains held",
    },
    {
        "member": "007-aib-case-page.html",
        "raw_sha256": "031290f1e9e2a1c55ed65ae8e1177472df4e0bd44c042fd8c0cdb1c205f4e612",
        "authority_identity_id": "neutral-citation:[2014] UKSC 58",
        "official_url": "https://supremecourt.uk/cases/uksc-2013-0052",
        "media_type": "text/html",
        "evidence_role": "IDENTITY_LANDING_ONLY_NOT_PROPOSITION_EVIDENCE",
        "exact_locators": [],
        "affected_row_ids": ["live30-q13:issue-08"],
        "jurisdiction_finding": "United Kingdom Supreme Court",
        "source_role_finding": "official case page used to locate the judgment bytes",
        "currentness_finding": "identity only",
        "later_treatment_finding": "not a treatment finding",
    },
    {
        "member": "008-aib-group-2014-uksc-58.pdf",
        "raw_sha256": "3a195e21d5adbaca9154f514074b106ab5104ad299dcfb4d029819603247203a",
        "authority_identity_id": "neutral-citation:[2014] UKSC 58",
        "official_url": "https://supremecourt.uk/uploads/uksc_2013_0052_judgment_1a74870f33.pdf",
        "media_type": "application/pdf",
        "evidence_role": "PROPOSED_OWNER_ADMISSION_REPRESENTATION",
        "exact_locators": ["paragraphs 63-66", "paragraphs 115-116", "paragraphs 134-141"],
        "affected_row_ids": ["live30-q13:issue-08"],
        "jurisdiction_finding": "United Kingdom Supreme Court",
        "source_role_finding": "binding Supreme Court judgment",
        "currentness_finding": "official judgment bytes and identity verified",
        "later_treatment_finding": "comprehensive later-treatment check remains held",
    },
    {
        "member": "009-infinity-distribution-2021-ewca-civ-565.xml",
        "raw_sha256": "1340b3522226dba8c4ec78fd18695abe3de54618765e968ab9345c2482b76dea",
        "authority_identity_id": "neutral-citation:[2021] EWCA Civ 565",
        "official_url": "https://caselaw.nationalarchives.gov.uk/ewca/civ/2021/565/data.xml",
        "media_type": "application/xml",
        "evidence_role": "PROPOSED_OWNER_ADMISSION_REPRESENTATION",
        "exact_locators": ["paragraphs 26-37", "paragraphs 44-52", "paragraphs 59-74"],
        "affected_row_ids": ["live60-q59:issue-15"],
        "jurisdiction_finding": "England and Wales; Court of Appeal (Civil Division)",
        "source_role_finding": "binding substitute only for the narrower ATE/security proposition",
        "currentness_finding": "historical judgment identity and exact spans verified",
        "later_treatment_finding": "comprehensive later-treatment check remains held",
    },
    {
        "member": "010-uksi-2024-1377-made.xml",
        "raw_sha256": "9f00dd106c5ed55009d7b5d90cfb78981a86851853fa1a0cade816dedb06f5db",
        "authority_identity_id": "uksi:2024:1377",
        "official_url": "https://www.legislation.gov.uk/uksi/2024/1377/made/data.xml",
        "media_type": "application/xml",
        "evidence_role": "MISIDENTIFIED_SOURCE_DIAGNOSTIC_NOT_ADMISSION",
        "exact_locators": ["regulation 1"],
        "affected_row_ids": ["live60-q37:issue-06"],
        "jurisdiction_finding": "extends to England and Wales, Scotland and Northern Ireland",
        "source_role_finding": "different instrument; not the cited LLP company-law instrument",
        "currentness_finding": "as-made identity verified",
        "later_treatment_finding": "not applicable to the rejected identity mapping",
    },
    {
        "member": "011-cpr-part-46.html",
        "raw_sha256": "aaffac83993737869bc4fdd44fac0ae4c4ff028fb80a160f05a0a116588d2b25",
        "authority_identity_id": "official-url:https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-46-costs-special-cases",
        "official_url": "https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-46-costs-special-cases",
        "media_type": "text/html",
        "evidence_role": "PROPOSED_OWNER_ADMISSION_REPRESENTATION",
        "exact_locators": ["CPR 46.9(1)-(4)"],
        "affected_row_ids": ["live30-q24:issue-08"],
        "jurisdiction_finding": "Civil Procedure Rules for England and Wales",
        "source_role_finding": "procedural rule, not proof of the retainer or bill facts",
        "currentness_finding": "current live page at retrieval; source-ceiling version remains held",
        "later_treatment_finding": "not a judgment; amendment/source-ceiling check remains held",
    },
    {
        "member": "012-pd57ad.html",
        "raw_sha256": "9c02ecbdebdcd27c57e236922dfb2a8bdcc4a3addee68fe1c73b9e60581ab1cc",
        "authority_identity_id": "official-url:https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-57a-business-and-property-courts/practice-direction-57ad-disclosure-in-the-business-and-property-courts",
        "official_url": "https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-57a-business-and-property-courts/practice-direction-57ad-disclosure-in-the-business-and-property-courts",
        "media_type": "text/html",
        "evidence_role": "PROPOSED_OWNER_ADMISSION_REPRESENTATION",
        "exact_locators": ["paragraphs 3.1-3.4", "paragraphs 4.1-4.5", "paragraphs 20.1-20.2"],
        "affected_row_ids": ["live30-q30:issue-18"],
        "jurisdiction_finding": "Business and Property Courts of England and Wales",
        "source_role_finding": "procedural practice direction",
        "currentness_finding": "current live page at retrieval; source-ceiling version remains held",
        "later_treatment_finding": "not a judgment; amendment/source-ceiling check remains held",
    },
    {
        "member": "013-sra-code-conduct-solicitors.html",
        "raw_sha256": "8d28c076345e5accbd07f0073bd6db2ace09d51524b64673b65f5546614ce59d",
        "authority_identity_id": "official-url:https://www.sra.org.uk/solicitors/standards-regulations/code-conduct-solicitors",
        "official_url": "https://www.sra.org.uk/solicitors/standards-regulations/code-conduct-solicitors/",
        "media_type": "text/html",
        "evidence_role": "PROPOSED_OWNER_ADMISSION_REPRESENTATION",
        "exact_locators": ["paragraphs 3.2, 3.3 and 3.5", "paragraph 8.6"],
        "affected_row_ids": ["live30-q05:issue-07", "live30-q24:issue-01", "live30-q24:issue-08"],
        "jurisdiction_finding": "SRA regulatory jurisdiction",
        "source_role_finding": "regulatory material; not independent legal authority",
        "currentness_finding": "current live page at retrieval; source-ceiling version remains held",
        "later_treatment_finding": "not a judgment; regulatory-version check remains held",
    },
    {
        "member": "014-uksi-2024-1377-latest.xml",
        "raw_sha256": "9f00dd106c5ed55009d7b5d90cfb78981a86851853fa1a0cade816dedb06f5db",
        "authority_identity_id": "uksi:2024:1377",
        "official_url": "https://www.legislation.gov.uk/uksi/2024/1377/data.xml",
        "media_type": "application/xml",
        "evidence_role": "MISIDENTIFIED_SOURCE_DIAGNOSTIC_NOT_ADMISSION",
        "exact_locators": ["regulation 1"],
        "affected_row_ids": ["live60-q37:issue-06"],
        "jurisdiction_finding": "extends to England and Wales, Scotland and Northern Ireland",
        "source_role_finding": "different instrument; latest and as-made URLs returned identical bytes",
        "currentness_finding": "identity confirmed; relevance mapping rejected",
        "later_treatment_finding": "not applicable to the rejected identity mapping",
    },
    {
        "member": "015-uksi-2024-234-made.xml",
        "raw_sha256": "2dffdcfcde1772e24746ca79d5845b26fd3de35f567fd30976c3335868129b98",
        "authority_identity_id": "uksi:2024:234",
        "official_url": "https://www.legislation.gov.uk/uksi/2024/234/made/data.xml",
        "media_type": "application/xml",
        "evidence_role": "PROPOSED_OWNER_ADMISSION_REPRESENTATION",
        "exact_locators": ["regulation 1", "regulation 5", "regulations 6-46 as relevant"],
        "affected_row_ids": ["live60-q37:issue-06"],
        "jurisdiction_finding": "extends to England and Wales, Scotland and Northern Ireland",
        "source_role_finding": "correctly titled LLP company-law amending instrument",
        "currentness_finding": "as-made identity verified; commencement/effects crosswalk remains held",
        "later_treatment_finding": "not a judgment; later amendments/effects remain held",
    },
)


ROW_FINDINGS: dict[str, dict[str, Any]] = {
    "live30-q01:issue-01": {
        "status": STATUS_RESOLVED,
        "source_refs": ["neutral-citation:[2016] EWCA Civ 982", "ukpga:1982:29"],
        "finding": "The candidate crosswalk for the 1982 Act is exact; Grand China already has sealed official quarantine bytes. Source presence does not prove the contract or breach facts.",
        "owner_action": "retain the proposition split and fact holds; no duplicate source proposal",
        "additional_holds": [
            "Grand China later treatment and owner admission remain outside this advisory"
        ],
    },
    "live30-q01:issue-03": {
        "status": STATUS_RESOLVED,
        "source_refs": [
            "neutral-citation:[2016] EWCA Civ 982",
            "neutral-citation:[2009] EWCA Civ 9",
        ],
        "finding": "Both Court of Appeal identities and locators have official bytes; the distinct waiver-of-strict-compliance proposition remains only partial.",
        "owner_action": "retain the waiver proposition and post-breach fact holds",
        "additional_holds": ["comprehensive later treatment remains held"],
    },
    "live30-q05:issue-06": {
        "status": STATUS_RESOLVED,
        "source_refs": ["neutral-citation:[2019] UKSC 5"],
        "finding": "Perry has exact official judgment bytes and supports valuation of a lost chance, but not assumed costs or every deduction.",
        "owner_action": "retain valuation-evidence and deduction-specific holds",
        "additional_holds": ["comprehensive later treatment remains held"],
    },
    "live30-q19:issue-01": {
        "status": STATUS_RESOLVED,
        "source_refs": ["ukpga:1998:41", "ukpga:2024:13"],
        "finding": "The Competition Act has exact 2026-08-14 official quarantine bytes and the DMCC Act has an exact candidate source-version crosswalk.",
        "owner_action": "retain the missing economic evidence and non-legislative-guidance role hold",
        "additional_holds": ["no judgment supplies a complete zero-price ecosystem methodology"],
    },
    "live30-q19:issue-03": {
        "status": STATUS_RESOLVED,
        "source_refs": ["ukpga:1998:41", "ukpga:2024:13"],
        "finding": "The statute identities and versions are exact; neither establishes a designation, imposed conduct requirement, dominance, abuse, effect or justification on the facts.",
        "owner_action": "retain the Competition Act application and DMCC designation holds",
        "additional_holds": [],
    },
    "live30-q19:issue-04": {
        "status": STATUS_RESOLVED,
        "source_refs": ["ukpga:1998:41", "ukpga:2024:13"],
        "finding": "The statute identities and versions are exact; exclusive-access terms, foreclosure and justification remain evidential questions.",
        "owner_action": "retain the arrangement and effect holds",
        "additional_holds": [],
    },
    "live30-q24:issue-01": {
        "status": STATUS_RESOLVED,
        "source_refs": [
            "official-url:https://www.sra.org.uk/solicitors/standards-regulations/code-conduct-solicitors",
            "ukpga:1982:29",
        ],
        "finding": "The 1982 Act candidate crosswalk is exact and the SRA Code now has official bytes. The SRA material is regulatory, not independent legal authority.",
        "owner_action": "admit the SRA bytes only through an exact regulatory lane and retain retainer/fact holds",
        "additional_holds": ["SRA source-ceiling version remains held"],
    },
    "live60-q42:issue-08": {
        "status": STATUS_RESOLVED,
        "source_refs": ["neutral-citation:[2011] EWCA Civ 1089", "neutral-citation:[2025] UKPC 34"],
        "finding": "Jardine candidate source-version source-version-8821b7dc63ebbb01d51e0ff2842f942cc23278cf is the exact judgment; the earlier mismatch was only the www.jcpc.uk versus jcpc.uk alias.",
        "owner_action": "retain the Bermuda/England-and-Wales role, later-treatment and relationship-fact holds",
        "additional_holds": [
            "Jardine is a Bermuda appeal and is not relabelled as an England-and-Wales binding judgment"
        ],
    },
    "live30-q04:issue-07": {
        "status": STATUS_RESOLVED,
        "source_refs": ["neutral-citation:[2022] EWCA Crim 832"],
        "finding": "R v Johnson paragraphs 49-50 provide an exact official Court of Appeal duress test and confirm the Hasan framework.",
        "owner_action": "rewrite the duress atom to the exact test, admit only the sealed Johnson bytes, and retain no-factual-basis application outcome",
        "additional_holds": ["comprehensive later treatment remains held"],
    },
    "live30-q05:issue-07": {
        "status": STATUS_REWRITE,
        "source_refs": [
            "official-url:https://www.sra.org.uk/solicitors/standards-regulations/code-conduct-solicitors"
        ],
        "finding": "Bounded primary-source research did not verify a binding AI-specific negligence rule. The exact SRA Code supports competence and supervision only and is regulatory material.",
        "owner_action": "remove any categorical AI-specific legal claim; retain an existing-duty/fact-specific atom or exclude the unsupported component",
        "additional_holds": ["the 17 August 2026 SRA warning remains post-ceiling and excluded"],
    },
    "live30-q13:issue-04": {
        "status": STATUS_RESOLVED,
        "source_refs": ["neutral-citation:[2025] UKSC 10", "neutral-citation:[2025] UKSC 43"],
        "finding": "The apparent Rukhadze collection failure is superseded by a separate successful official representation of the same identity; Day and Mitchell also have official bytes.",
        "owner_action": "retain transaction, authorisation, loss, profit and remedy-selection holds",
        "additional_holds": [],
    },
    "live30-q13:issue-08": {
        "status": STATUS_RESOLVED,
        "source_refs": ["neutral-citation:[2014] UKSC 58"],
        "finding": "The failed legacy AIB PDF route returned HTML; a different official case-page route yielded the exact 45-page judgment PDF.",
        "owner_action": "admit only the sealed replacement PDF and retain Menelaou treatment, tracing and remedy-selection holds",
        "additional_holds": ["mixed-account and recipient facts remain missing"],
    },
    "live30-q20:issue-08": {
        "status": STATUS_REWRITE,
        "source_refs": ["neutral-citation:[2015] UKSC 11", "neutral-citation:[2023] UKSC 26"],
        "finding": "The identified Supreme Court cases support ordinary clinical duties; bounded primary-source research did not verify a free-standing AI-specific verification duty.",
        "owner_action": "retain only the ordinary-duty atom and exclude any categorical AI-specific rule",
        "additional_holds": [
            "device status, validation, governance, knowledge and accepted practice remain matter facts"
        ],
    },
    "live30-q24:issue-08": {
        "status": STATUS_RESOLVED,
        "source_refs": [
            "official-url:https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-46-costs-special-cases",
            "official-url:https://www.sra.org.uk/solicitors/standards-regulations/code-conduct-solicitors",
        ],
        "finding": "The www.justice.gov.uk route resolves CPR 46.9; the SRA Code and Transparency Rules remain regulatory materials.",
        "owner_action": "use only the exact procedural/regulatory roles and retain retainer, bill, approval and accessibility facts",
        "additional_holds": ["live-page source-ceiling versions remain held"],
    },
    "live30-q28:issue-05": {
        "status": STATUS_RETAINED,
        "source_refs": ["neutral-citation:[2001] UKHL 44", "neutral-citation:[2025] UKSC 22"],
        "finding": "The official Parliament representation for Etridge remains HTTP 403 after the bounded diagnosed route; Waller-Edwards is an exact candidate Supreme Court source but cannot silently replace every Etridge span.",
        "owner_action": "retain the Etridge representation hold or rewrite solely to exact Waller-Edwards propositions",
        "additional_holds": [
            "transaction, relationship, notice and lender-response facts remain missing"
        ],
    },
    "live30-q30:issue-07": {
        "status": STATUS_REWRITE,
        "source_refs": [],
        "finding": "The unsupported component is a route-selection warning, not an atomic positive legal rule requiring a new source identity.",
        "owner_action": "rewrite as analysis or exclude it from source-qualified components",
        "additional_holds": ["retain each statutory route and remedy as a separate sourced atom"],
    },
    "live30-q30:issue-10": {
        "status": STATUS_REWRITE,
        "source_refs": [],
        "finding": "A prioritised litigation and settlement strategy is evidence-dependent professional analysis, not a source-verifiable legal proposition.",
        "owner_action": "rewrite as non-authority analysis or exclude from qualification",
        "additional_holds": [
            "objectives, evidence, limitation, assets, funding, costs and enforcement facts remain missing"
        ],
    },
    "live30-q30:issue-16": {
        "status": STATUS_REWRITE,
        "source_refs": [],
        "finding": "The remaining trade-secret component turns on secrecy, reasonable protection, acquisition/use and product facts; no source can prove those matter facts.",
        "owner_action": "retain the sourced legal tests and classify the unsupported application as a matter-information hold",
        "additional_holds": ["do not invent a trade-secret outcome"],
    },
    "live30-q30:issue-18": {
        "status": STATUS_RESOLVED,
        "source_refs": [
            "official-url:https://www.justice.gov.uk/courts/procedure-rules/civil/rules/part-57a-business-and-property-courts/practice-direction-57ad-disclosure-in-the-business-and-property-courts"
        ],
        "finding": "The www.justice.gov.uk route resolves the PD57AD source and exact preservation, continuing-duty and sanction locators.",
        "owner_action": "admit only the sealed live-page bytes and retain deletion chronology, relevance, actor and consequence facts",
        "additional_holds": ["source-ceiling version remains held"],
    },
    "live60-q32:issue-04": {
        "status": STATUS_RESOLVED,
        "source_refs": ["neutral-citation:[2023] EWCA Civ 884", "neutral-citation:[2019] UKPC 38"],
        "finding": "Dyson supplies current England-and-Wales appellate identification/reference authority. Simon was recovered but remains a persuasive Privy Council appeal from Trinidad and Tobago.",
        "owner_action": "prefer the exact Dyson spans and retain words, context, audience, extrinsic-knowledge and serious-harm facts",
        "additional_holds": ["Simon is not promoted to binding England-and-Wales authority"],
    },
    "live60-q37:issue-06": {
        "status": STATUS_RESOLVED,
        "source_refs": ["uksi:2024:234", "uksi:2024:1377"],
        "finding": "Official bytes prove SI 2024/1377 is a different protection-and-disclosure instrument. The correctly titled Limited Liability Partnerships (Application of Company Law) Regulations 2024 are SI 2024/234.",
        "owner_action": "reject the SI 2024/1377 identity mapping; consider exact admission of SI 2024/234 only after commencement/effects crosswalk",
        "additional_holds": [
            "exact applied provisions, commencement, LLP agreement, distributions and insolvency effects remain held"
        ],
    },
    "live60-q40:issue-09": {
        "status": STATUS_RETAINED,
        "source_refs": ["ukpga:1981:54"],
        "finding": "The Senior Courts Act and CPR sources cover final judicial-review remedies, but no proposition-complete official interim-relief authority was selected in the bounded run.",
        "owner_action": "retain the interim-relief source gap and all remedy-application facts",
        "additional_holds": [
            "construction timing, third parties, delay, likely outcome, damages basis and undertaking evidence remain missing"
        ],
    },
    "live60-q42:issue-03": {
        "status": STATUS_RETAINED,
        "source_refs": [
            "neutral-citation:[2004] UKHL 48",
            "neutral-citation:[2026] EWHC 877 (Comm)",
        ],
        "finding": "The official Parliament representation for Three Rivers No 6 remains HTTP 403; other client-group and litigation-privilege sources do not remove that exact waiver/ownership span hold.",
        "owner_action": "retain the unavailable representation and Aabar first-instance/later-treatment holds",
        "additional_holds": [
            "corporate authority, employee roles, purpose and disclosure facts remain missing"
        ],
    },
    "live60-q46:issue-05": {
        "status": STATUS_REWRITE,
        "source_refs": [],
        "finding": "The exact minimum disclosure needed is matter- and procedure-specific; it is not a freestanding legal proposition for which a source identity can be supplied.",
        "owner_action": "retain the sourced safeguards and classify the minimum-disclosure application as a matter-information hold",
        "additional_holds": [
            "withheld information, trade secret ownership and proposed safeguards remain unidentified"
        ],
    },
    "live60-q50:issue-06": {
        "status": STATUS_RETAINED,
        "source_refs": ["neutral-citation:[2003] UKHL 48"],
        "finding": "The official Parliament representation for Lloyds TSB remains HTTP 403. Later UKSC/EWCA aggregation sources are available but cannot silently substitute the exact missing span.",
        "owner_action": "retain the Lloyds representation hold or rewrite solely to exact available later authorities",
        "additional_holds": [
            "exact clause, limits, retentions, policy periods and post-2024 treatment remain held"
        ],
    },
    "live60-q59:issue-14": {
        "status": STATUS_REWRITE,
        "source_refs": [],
        "finding": "The no-universal-control-or-full-disclosure statement is a caution about route and facts, not a positive legal rule needing a new source identity.",
        "owner_action": "rewrite as a no-conclusion/matter-information hold or exclude the component",
        "additional_holds": [
            "agreement, route, representative, security, costs, control, disclosure and privilege facts remain missing"
        ],
    },
    "live60-q59:issue-15": {
        "status": STATUS_RESOLVED,
        "source_refs": [
            "neutral-citation:[2021] EWCA Civ 565",
            "neutral-citation:[2021] EWCA Civ 1452",
        ],
        "finding": "Doyle's official landing page confirms identity but supplies no proposition bytes. Infinity is an official Court of Appeal substitute for a narrower ATE/security-form proposition, not for unidentified policy terms.",
        "owner_action": "rewrite to the exact Infinity proposition and admit its sealed bytes; keep Doyle and all product facts held",
        "additional_holds": [
            "policy wording, insurer, rating, limit, premium, exclusions, deed, route and later treatment remain held"
        ],
    },
    "live60-q59:issue-17": {
        "status": STATUS_RESOLVED,
        "source_refs": ["neutral-citation:[2026] UKSC 24"],
        "finding": "A different official UKSC route recovered the full AXA judgment. The universal-distribution component remains route- and fact-specific rather than a missing-source proposition.",
        "owner_action": "admit only the sealed AXA representation and rewrite/exclude the universal-distribution component",
        "additional_holds": [
            "route, class, orders, method, proof, settlement, costs, funding and unclaimed sums remain missing"
        ],
    },
}


def _validate_input(file_path: Path, expected_file_sha256: str) -> dict[str, Any]:
    if _sha256_file(file_path) != expected_file_sha256:
        raise ValueError(f"sealed input hash mismatch: {_relative(file_path)}")
    return json.loads(file_path.read_text(encoding="utf-8"))


def _validate_source_files() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    expected_members = {entry["member"] for entry in SOURCE_FILES}
    actual_members = {entry.name for entry in OFFICIAL_ROOT.iterdir() if entry.is_file()}
    if actual_members != expected_members:
        raise ValueError("quarantine source member set mismatch")
    for entry in SOURCE_FILES:
        source_path = OFFICIAL_ROOT / entry["member"]
        if _sha256_file(source_path) != entry["raw_sha256"]:
            raise ValueError(f"source byte hash mismatch: {entry['member']}")
        record = dict(entry)
        record["bytes"] = source_path.stat().st_size
        record["quarantine_path"] = _relative(source_path)
        record["source_admission_authorized"] = False
        record["source_admitted"] = False
        record["indexed"] = False
        record["embedded"] = False
        record["record_content_sha256"] = _content_sha256(record)
        records.append(record)
    return records


def _set_sha256(row_ids: tuple[str, ...]) -> str:
    return _sha256(("\n".join(row_ids) + "\n").encode("utf-8"))


def _assert_no_absolute_paths(value: Any) -> None:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if _PRIVATE_PATH.search(rendered):
        raise ValueError("artifact contains an absolute local path")


def _build_retry_ledger(prior_manifest: dict[str, Any]) -> dict[str, Any]:
    assigned = set(HELD8) | set(MISSING20)
    prior_failures: list[dict[str, Any]] = []
    for record in prior_manifest["records"]:
        affected = sorted(assigned.intersection(record.get("affected_row_ids", [])))
        if not affected or record.get("result") == "DOWNLOADED_QUARANTINED_BOUND":
            continue
        prior_failures.append(
            {
                "authority_identity_id": record["authority_identity_id"],
                "affected_row_ids": affected,
                "failed_url": record.get("requested_url") or record.get("official_urls", [None])[0],
                "failure_fingerprint": {
                    "error_code": record.get("error_code"),
                    "http_status": record.get("http_status"),
                    "result": record.get("result"),
                },
                "unchanged_retry_prohibited": True,
                "disposition": "STOPPED_OR_DIFFERENT_OFFICIAL_ROUTE_ONLY",
            }
        )
    prior_failures.sort(key=lambda item: (item["authority_identity_id"], item["affected_row_ids"]))
    ledger = {
        "schema": "legalbot.v111.phase2a.held-missing-source-anti-retry-ledger.v1",
        "status": "SEALED_BOUNDED_DIAGNOSTICS_NO_UNCHANGED_RETRY",
        "assigned_row_count": 28,
        "prior_failure_count": len(prior_failures),
        "prior_failures": prior_failures,
        "additional_diagnostics": [
            {
                "authority_identity_id": "neutral-citation:[2014] UKSC 58",
                "failed_route": "https://supremecourt.uk/cases/docs/uksc-2013-0052-judgment.pdf",
                "failure_fingerprint": "HTTP_200_WRONG_MEDIA_TYPE_TEXT_HTML",
                "evidence_member": "003-aib-group-2014-uksc-58-wrong-media-type.html",
                "unchanged_retry_prohibited": True,
                "different_official_route_result": "VALID_PDF_RECOVERED_AS_MEMBER_008",
            },
            {
                "authority_identity_id": "uksi:2024:1377",
                "failed_route": "original point-in-time URL from the prior collector",
                "failure_fingerprint": "HTTP_404_AND_SUBSEQUENT_IDENTITY_MISMATCH",
                "unchanged_retry_prohibited": True,
                "different_official_route_result": "IDENTITY_PROVED_DIFFERENT; CORRECT_INSTRUMENT_UKSI_2024_234",
            },
        ],
        **NO_EXECUTION,
    }
    return _seal(ledger)


def build_artifacts(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Path]:
    if output_root.exists():
        raise FileExistsError(f"create-only output already exists: {output_root}")
    if _set_sha256(HELD8) != HELD8_SET_SHA256:
        raise ValueError("held8 set hash mismatch")
    if _set_sha256(MISSING20) != MISSING20_SET_SHA256:
        raise ValueError("missing20 set hash mismatch")
    if set(HELD8) & set(MISSING20):
        raise ValueError("assigned groups overlap")
    if set(ROW_FINDINGS) != set(HELD8) | set(MISSING20):
        raise ValueError("row advisory mapping is not exact")

    r3 = _validate_input(R3_REPORT, R3_REPORT_FILE_SHA256)
    owner_packet = _validate_input(OWNER_PACKET, OWNER_PACKET_FILE_SHA256)
    prior_manifest = _validate_input(
        PRIOR_QUARANTINE_MANIFEST, PRIOR_QUARANTINE_MANIFEST_FILE_SHA256
    )
    candidate_manifest = _validate_input(CANDIDATE_MANIFEST, CANDIDATE_MANIFEST_FILE_SHA256)
    if r3["artifact_content_sha256"] != R3_REPORT_CONTENT_SHA256:
        raise ValueError("r3 logical content hash mismatch")
    if owner_packet["artifact_content_sha256"] != OWNER_PACKET_CONTENT_SHA256:
        raise ValueError("owner packet logical content hash mismatch")
    if prior_manifest["manifest_content_sha256"] != PRIOR_QUARANTINE_MANIFEST_CONTENT_SHA256:
        raise ValueError("prior quarantine logical content hash mismatch")

    r3_by_row = {row["row_id"]: row for row in r3["rows"]}
    owner_by_row = {row["row_id"]: row for row in owner_packet["decisions"]}
    assigned = set(HELD8) | set(MISSING20)
    if not assigned <= set(r3_by_row) or not assigned <= set(owner_by_row):
        raise ValueError("assigned row missing from sealed inputs")

    candidate_by_identity = {
        source["authority_identity_id"]: source for source in candidate_manifest["sources"]
    }
    expected_crosswalks = {
        "ukpga:1982:29": "source-version-16a9bcb428d17e0126ba147b0903bece7823d595",
        "ukpga:2024:13": "source-version-7fee99e6ed2c3550f4cec74060757ca20a872635",
        "neutral-citation:[2025] UKPC 34": "source-version-8821b7dc63ebbb01d51e0ff2842f942cc23278cf",
    }
    for identity, source_version_id in expected_crosswalks.items():
        if candidate_by_identity[identity]["source_version_id"] != source_version_id:
            raise ValueError(f"candidate crosswalk mismatch: {identity}")

    source_records = _validate_source_files()
    source_manifest = _seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-official-source-research-manifest.v1",
            "status": "QUARANTINED_RESEARCH_ONLY_NOT_ADMITTED_NOT_INDEXED",
            "source_ceiling_date": "2026-08-14",
            "retrieval_date": "2026-08-28",
            "official_primary_sources_only": True,
            "record_count": len(source_records),
            "evidence_role_counts": dict(
                sorted(Counter(record["evidence_role"] for record in source_records).items())
            ),
            "records": source_records,
            "identity_corrections": [
                {
                    "row_id": "live60-q37:issue-06",
                    "rejected_identity_id": "uksi:2024:1377",
                    "rejected_title_claim": "Limited Liability Partnerships (Application of Company Law) Regulations 2024",
                    "official_title_for_rejected_identity": "Companies and Limited Liability Partnerships (Protection and Disclosure of Information and Consequential Amendments) Regulations 2024",
                    "correct_identity_id": "uksi:2024:234",
                    "correct_title": "Limited Liability Partnerships (Application of Company Law) Regulations 2024",
                    "automatic_substitution": False,
                    "owner_admission_required": True,
                    "commencement_effects_currentness_hold_retained": True,
                }
            ],
            **NO_EXECUTION,
        }
    )

    row_records: list[dict[str, Any]] = []
    for row_id in (*HELD8, *MISSING20):
        finding = ROW_FINDINGS[row_id]
        baseline = owner_by_row[row_id]
        row_record = {
            "schema": "legalbot.v111.phase2a.held-missing-source-row-advisory.v1",
            "row_id": row_id,
            "assigned_topology_group": (
                "SOURCE_PRESENT_BUT_ASSESSMENT_HELD"
                if row_id in HELD8
                else "MISSING_SOURCE_IDENTITY"
            ),
            "issue_label": baseline["source_queue_record"]["issue_label"],
            "baseline_owner_decision_content_sha256": baseline["decision_content_sha256"],
            "baseline_prequalification_record_content_sha256": r3_by_row[row_id][
                "record_content_sha256"
            ],
            "topology_disposition": finding["status"],
            "source_identity_or_requirement_resolution": finding["finding"],
            "authority_identity_references": finding["source_refs"],
            "recommended_owner_action": finding["owner_action"],
            "baseline_unresolved_holds": baseline["source_research_record"]["unresolved_holds"],
            "additional_retained_holds": finding["additional_holds"],
            "owner_decision_required": True,
            "material_gap_cleared": False,
            "technical_qualification_assigned": False,
            "answer_release_eligible": False,
            "row_record_content_sha256": None,
        }
        row_record["row_record_content_sha256"] = _content_sha256(
            {key: value for key, value in row_record.items() if key != "row_record_content_sha256"}
        )
        row_records.append(row_record)

    status_counts = Counter(record["topology_disposition"] for record in row_records)
    advisory = _seal(
        {
            "schema": "legalbot.v111.phase2a.held-missing-source-advisory-28.v1",
            "status": "READY_FOR_CONSOLIDATION_NOT_OWNER_ADOPTED_NOT_EXECUTED",
            "revision": {
                "supersedes_r1_advisory_content_sha256": SUPERSEDED_R1_ADVISORY_CONTENT_SHA256,
                "supersedes_r1_advisory_file_sha256": SUPERSEDED_R1_ADVISORY_FILE_SHA256,
                "reason": "correct the Simon v Lyder official JCPC PDF URL; findings, row sets, source bytes and dispositions are unchanged",
            },
            "scope": {
                "source_present_but_assessment_held_row_ids": list(HELD8),
                "source_present_but_assessment_held_set_sha256": HELD8_SET_SHA256,
                "missing_source_identity_row_ids": list(MISSING20),
                "missing_source_identity_set_sha256": MISSING20_SET_SHA256,
                "overlap_count": 0,
                "total_row_count": 28,
            },
            "input_bindings": {
                "r3_report_content_sha256": R3_REPORT_CONTENT_SHA256,
                "r3_report_file_sha256": R3_REPORT_FILE_SHA256,
                "owner_packet_content_sha256": OWNER_PACKET_CONTENT_SHA256,
                "owner_packet_file_sha256": OWNER_PACKET_FILE_SHA256,
                "prior_quarantine_manifest_content_sha256": PRIOR_QUARANTINE_MANIFEST_CONTENT_SHA256,
                "prior_quarantine_manifest_file_sha256": PRIOR_QUARANTINE_MANIFEST_FILE_SHA256,
                "candidate_manifest_file_sha256": CANDIDATE_MANIFEST_FILE_SHA256,
            },
            "result_counts": {
                "row_advisory_count": len(row_records),
                "source_topology_resolved_owner_action_required": status_counts[STATUS_RESOLVED],
                "no_valid_missing_source_requirement_owner_rewrite_or_exclusion": status_counts[
                    STATUS_REWRITE
                ],
                "unavailable_or_incomplete_official_source_gap_retained": status_counts[
                    STATUS_RETAINED
                ],
                "rows_with_any_retained_hold": 28,
                "rows_automatically_qualified": 0,
                "new_source_admission_representations_proposed": sum(
                    record["evidence_role"] == "PROPOSED_OWNER_ADMISSION_REPRESENTATION"
                    for record in source_records
                ),
            },
            "candidate_crosswalk_repairs": [
                {
                    "authority_identity_id": identity,
                    "source_version_id": source_version_id,
                    "owner_decision_applied": False,
                }
                for identity, source_version_id in expected_crosswalks.items()
            ],
            "legal_accuracy_controls": {
                "official_primary_sources_only": True,
                "bounded_search_not_comprehensive_citator": True,
                "no_negative_treatment_inference_from_search_silence": True,
                "judgment_later_treatment_holds_preserved": True,
                "live_rule_and_regulator_source_ceiling_holds_preserved": True,
                "persuasive_sources_not_relabelled_binding": True,
                "regulatory_material_not_relabelled_independent_legal_authority": True,
                "matter_facts_not_converted_to_source_gaps": True,
                "source_presence_does_not_upgrade_partial_or_none_support": True,
            },
            "rows": row_records,
            **NO_EXECUTION,
        }
    )
    retry_ledger = _build_retry_ledger(prior_manifest)

    for value in (advisory, source_manifest, retry_ledger):
        _assert_no_absolute_paths(value)

    temp_parent = output_root.parent
    temp_parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=temp_parent))
    try:
        artifacts = {
            ADVISORY_NAME: advisory,
            SOURCE_MANIFEST_NAME: source_manifest,
            RETRY_LEDGER_NAME: retry_ledger,
        }
        for name, value in artifacts.items():
            (temp_root / name).write_bytes(_pretty_json(value))
            os.chmod(temp_root / name, 0o600)

        package_records = []
        for name, value in sorted(artifacts.items()):
            package_records.append(
                {
                    "name": name,
                    "file_sha256": _sha256_file(temp_root / name),
                    "content_sha256": value["artifact_content_sha256"],
                    "bytes": (temp_root / name).stat().st_size,
                }
            )
        package = _seal(
            {
                "schema": "legalbot.v111.phase2a.held-missing-source-advisory-package.v1",
                "status": "CREATE_ONLY_RESEARCH_ADVISORY_NOT_AUTHORITY",
                "artifact_count": len(package_records),
                "artifacts": package_records,
                **NO_EXECUTION,
            },
            field="package_content_sha256",
        )
        (temp_root / PACKAGE_NAME).write_bytes(_pretty_json(package))
        os.chmod(temp_root / PACKAGE_NAME, 0o600)

        checksum_names = sorted([*artifacts, PACKAGE_NAME])
        checksums = "".join(
            f"{_sha256_file(temp_root / name)}  {name}\n" for name in checksum_names
        )
        (temp_root / CHECKSUMS_NAME).write_text(checksums, encoding="utf-8")
        os.chmod(temp_root / CHECKSUMS_NAME, 0o600)
        temp_root.rename(output_root)
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise

    return {
        "advisory": output_root / ADVISORY_NAME,
        "source_manifest": output_root / SOURCE_MANIFEST_NAME,
        "retry_ledger": output_root / RETRY_LEDGER_NAME,
        "package": output_root / PACKAGE_NAME,
        "checksums": output_root / CHECKSUMS_NAME,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    paths = build_artifacts(args.output_root.resolve())
    for label, file_path in paths.items():
        print(f"{label}: {file_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
